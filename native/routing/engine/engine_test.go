package engine

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func keys(t *testing.T) (string, string) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// This is a real sing-box DNS/FakeIP + route + AWG integration test, using
// loopback underlay sockets. It does not claim device TUN or native OS policy
// coverage. Both domains resolve to 10.77.0.2. The test DIRECT socket factory
// maps that observer to loopback; VPN uses the real AWG stack at 10.77.0.2.
func TestFakeIPSharedAddressEgress(t *testing.T) {
	for _, policy := range []rules.Action{rules.VPN, rules.Direct} {
		t.Run(string(policy), func(t *testing.T) { testFakeIPSharedAddressEgress(t, policy) })
	}
}

func testFakeIPSharedAddressEgress(t *testing.T, defaultPolicy rules.Action) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	aPriv, aPub := keys(t)
	bPriv, bPub := keys(t)
	var lc net.ListenConfig
	listen := func(ctx context.Context, n, a string) (net.PacketConn, error) { return lc.ListenPacket(ctx, n, a) }
	// Reserve the client's outer port so both peers have fixed endpoints.
	reserved, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	aPort := uint16(reserved.LocalAddr().(*net.UDPAddr).Port)
	reserved.Close()
	params := map[string]string{"jc": "2", "jmin": "40", "jmax": "80", "s1": "16", "s2": "24", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}
	b, e := awg.New(ctx, awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.2")}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), aPort), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")}, Parameters: params}, listen)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	bPort, e := b.LocalPort()
	if e != nil {
		t.Fatal(e)
	}
	physical, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer physical.Close()
	port := uint16(physical.Addr().(*net.TCPAddr).Port)
	virtual, e := b.Net.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.77.0.2"), port))
	if e != nil {
		t.Fatal(e)
	}
	defer virtual.Close()
	var directConnections atomic.Int32
	serve := func(l net.Listener, marker string) {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			if marker == "DIRECT" {
				directConnections.Add(1)
			}
			go func() { defer c.Close(); io.WriteString(c, marker) }()
		}
	}
	go serve(physical, "DIRECT")
	go serve(virtual, "TUNNEL")
	route, e := (rules.Config{Version: 1, Default: defaultPolicy, Rules: []rules.Rule{{Kind: rules.Suffix, Value: "*.direct.test", Action: rules.Direct}, {Kind: rules.Domain, Value: "b.vpn.test", Action: rules.VPN}}}).Compile()
	if e != nil {
		t.Fatal(e)
	}
	var routeConfig map[string]any
	json.Unmarshal(route, &routeConfig)
	routeConfig["default_domain_resolver"] = "real"
	config := map[string]any{
		"dns": map[string]any{"servers": []any{
			map[string]any{"type": "hosts", "tag": "real", "predefined": map[string]any{"a.direct.test": "10.77.0.2", "b.vpn.test": "10.77.0.2", "unlisted.test": "10.77.0.2"}},
			map[string]any{"type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"},
		}, "rules": []any{map[string]any{"inbound": []string{"test-capture"}, "query_type": []string{"A", "AAAA"}, "action": "route", "server": "fake"}}, "final": "real", "reverse_mapping": false},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}, map[string]any{
			"type": "amneziawg", "tag": "vpn", "address": []string{"10.77.0.1"}, "private_key": aPriv, "public_key": bPub, "endpoint": netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), bPort).String(), "listen_port": aPort, "allowed_ips": []string{"10.77.0.2/32"}, "parameters": params,
		}}, "route": routeConfig,
	}
	raw, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	ctx = Context(ctx, Underlay{ListenPacket: listen, DialContext: func(c context.Context, n, a string) (net.Conn, error) {
		destination, e := netip.ParseAddrPort(a)
		if e != nil {
			return nil, e
		}
		if destination.Addr() == netip.MustParseAddr("10.77.0.2") {
			a = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), destination.Port()).String()
		}
		var dial net.Dialer
		return dial.DialContext(c, n, a)
	}})
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
	instance, e := New(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = instance.Start(); e != nil {
		t.Fatal(e)
	}
	defer instance.Close()
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	dnsManager := service.FromContext[adapter.DNSTransportManager](ctx)
	fake, ok := dnsManager.Transport("fake")
	if !ok {
		t.Fatal("missing fake DNS")
	}
	seen := map[string]bool{}
	var vpnFakeIP netip.Addr
	defaultObserver := "TUNNEL"
	expectedDirect := int32(1)
	if defaultPolicy == rules.Direct {
		defaultObserver = "DIRECT"
		expectedDirect++
	}
	for _, v := range []struct{ domain, want string }{{"a.direct.test", "DIRECT"}, {"b.vpn.test", "TUNNEL"}, {"unlisted.test", defaultObserver}} {
		query := new(dns.Msg)
		query.SetQuestion(dns.Fqdn(v.domain), dns.TypeA)
		response, e := dnsRouter.Exchange(ctx, query, adapter.DNSQueryOptions{Transport: fake})
		if e != nil {
			t.Fatal(e)
		}
		ip := response.Answer[0].(*dns.A).A.String()
		if seen[ip] {
			t.Fatal("domains received same fake address")
		}
		seen[ip] = true
		if v.domain == "b.vpn.test" {
			vpnFakeIP = netip.MustParseAddr(ip)
		}
		app, router := net.Pipe()
		app.SetDeadline(time.Now().Add(8 * time.Second))
		go instance.Router().RouteConnectionEx(ctx, router, adapter.InboundContext{Inbound: "test-capture", Network: "tcp", Source: M.ParseSocksaddr("127.0.0.1:12345"), Destination: M.Socksaddr{Addr: netip.MustParseAddr(ip), Port: port}}, nil)
		buf := make([]byte, len(v.want))
		_, e = io.ReadFull(app, buf)
		app.Close()
		if e != nil {
			t.Fatalf("%s: %v", v.domain, e)
		}
		if string(buf) != v.want {
			t.Fatalf("%s egress: got %q", v.domain, buf)
		}
	}
	// An app may retain a FakeIP whose mapping was removed. Never pass that
	// literal into DIRECT or AWG; the missing identity must fail at routing.
	for _, address := range []string{"198.19.255.1", "fc00:3fff::1"} {
		app, capture := net.Pipe()
		closed := make(chan error, 1)
		instance.Router().RouteConnectionEx(ctx, capture, adapter.InboundContext{Inbound: "test-capture", Network: "tcp", Destination: M.Socksaddr{Addr: netip.MustParseAddr(address), Port: port}}, func(err error) { closed <- err })
		select {
		case err := <-closed:
			if err == nil || !strings.Contains(err.Error(), "missing fakeip record") {
				t.Fatal("unmapped FakeIP was not rejected before egress", err)
			}
		case <-time.After(time.Second):
			t.Fatal("unmapped FakeIP reached an outbound")
		}
		app.Close()
	}
	// Exercise the router's UDP copy path, not just Transport.DialContext.
	// The actual Android APK exposed a timeout here despite passing TCP and
	// connected-UDP transport tests.
	udp, e := b.Net.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.77.0.2"), port))
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		p := make([]byte, 1024)
		for {
			_, from, err := udp.ReadFrom(p)
			if err != nil {
				return
			}
			udp.WriteTo([]byte("TUNNEL"), from)
		}
	}()
	udpApp, udpCapture := net.Pipe()
	udpApp.SetDeadline(time.Now().Add(2 * time.Second))
	udpDestination := M.Socksaddr{Addr: vpnFakeIP, Port: port}
	udpClosed := make(chan error, 1)
	go instance.Router().RoutePacketConnectionEx(ctx, bufio.NewUnbindPacketConnWithAddr(udpCapture, udpDestination), adapter.InboundContext{Inbound: "test-capture", Network: "udp", Destination: udpDestination}, func(err error) { udpClosed <- err })
	if _, e := udpApp.Write([]byte("UDP")); e != nil {
		t.Fatal(e)
	}
	udpReply := make([]byte, 6)
	_, e = io.ReadFull(udpApp, udpReply)
	udpApp.Close()
	if e != nil || string(udpReply) != "TUNNEL" {
		select {
		case err := <-udpClosed:
			t.Log("UDP close reason", err)
		default:
		}
		t.Fatalf("FakeIP UDP route: %q, %v", udpReply, e)
	}
	// Drop the remote transport, then open a fresh VPN-assigned flow. It must
	// fail, and must never reach the DIRECT observer.
	b.Close()
	failedCtx, failedCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer failedCancel()
	app, router := net.Pipe()
	defer app.Close()
	app.SetDeadline(time.Now().Add(time.Second))
	go instance.Router().RouteConnectionEx(failedCtx, router, adapter.InboundContext{Inbound: "test-capture", Network: "tcp", Destination: M.Socksaddr{Addr: vpnFakeIP, Port: port}}, nil)
	if n, _ := app.Read(make([]byte, 16)); n != 0 {
		t.Fatal("unavailable VPN returned data")
	}
	if directConnections.Load() != expectedDirect {
		t.Fatal("VPN failure fell back to DIRECT")
	}
}

// The test host forbids netlink sockets. This supplies only the loopback
// inventory needed by the flow test, with no OS route monitoring claims.
type loopbackTestPlatform struct{ adapter.PlatformInterface }

func (loopbackTestPlatform) Initialize(adapter.NetworkManager) error  { return nil }
func (loopbackTestPlatform) UsePlatformDefaultInterfaceMonitor() bool { return true }
func (loopbackTestPlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}
func (loopbackTestPlatform) UsePlatformNetworkInterfaces() bool { return true }
func (loopbackTestPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return []adapter.NetworkInterface{{Interface: control.Interface{Index: 1, Name: "lo", Addresses: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}}}}, nil
}
func (loopbackTestPlatform) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (loopbackTestPlatform) UnderNetworkExtension() bool                 { return false }
func (loopbackTestPlatform) UsePlatformConnectionOwnerFinder() bool      { return false }
func (loopbackTestPlatform) UsePlatformNeighborResolver() bool           { return false }
func (loopbackTestPlatform) UsePlatformWIFIMonitor() bool                { return false }
func (loopbackTestPlatform) MyInterfaceAddress() []netip.Addr            { return nil }
