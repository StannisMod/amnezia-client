//go:build !android && !ios

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// Verify the fixture peer really learns an authenticated ephemeral endpoint;
// production's pinned-endpoint outbound is unchanged by the test server.
func TestEmulatorPeerLearnsEndpointAndServesIPv4IPv6(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	f := &fixture{server: server, client: client}
	if err := f.start(); err != nil {
		t.Fatal(err)
	}
	defer f.stop()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transport, err := awg.New(ctx, awg.Config{
		Address:    []netip.Addr{netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("fd77::1")},
		PrivateKey: base64.StdEncoding.EncodeToString(client.Bytes()), PublicKey: base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()),
		Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), f.listenPort), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		Parameters: map[string]string{"jc": "3", "jmin": "40", "jmax": "80", "s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"},
	}, func(ctx context.Context, network, address string) (net.PacketConn, error) {
		var lc net.ListenConfig
		return lc.ListenPacket(ctx, network, address)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	c0, err := transport.DialContext(ctx, "udp", "10.77.0.2:53")
	if err != nil {
		t.Fatal(err)
	}
	c0.SetDeadline(time.Now().Add(2 * time.Second))
	for i, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
		q := new(dns.Msg)
		q.SetQuestion("burst.test.", kind)
		q.Id = uint16(100 + i)
		raw, _ := q.Pack()
		if _, err := c0.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	seenResponses := make(map[uint16]bool)
	for i := 0; i < 2; i++ {
		b := make([]byte, 4096)
		n, e := c0.Read(b)
		if e != nil {
			t.Fatal("burst DNS", i, e)
		}
		a := new(dns.Msg)
		if err := a.Unpack(b[:n]); err != nil || a.Id < 100 || a.Id > 101 || seenResponses[a.Id] {
			t.Fatal("invalid or duplicate burst response", err)
		}
		seenResponses[a.Id] = true
	}
	c0.Close()
	for _, ip := range []string{sharedIP, "fd77::2"} {
		c, err := transport.DialContext(ctx, "tcp", net.JoinHostPort(ip, "18081"))
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		data, err := io.ReadAll(c)
		c.Close()
		if err != nil || string(data) != "VPN\n" {
			t.Fatalf("TCP observer: %q, %v", data, err)
		}
		u, err := transport.DialContext(ctx, "udp", net.JoinHostPort(ip, "18082"))
		if err != nil {
			t.Fatal(err)
		}
		u.SetDeadline(time.Now().Add(3 * time.Second))
		u.Write([]byte("probe"))
		buf := make([]byte, 32)
		n, err := u.Read(buf)
		u.Close()
		if err != nil || string(buf[:n]) != "VPN:probe" {
			t.Fatalf("UDP observer: %q, %v", buf[:n], err)
		}
	}
	for _, query := range []struct {
		name    string
		kind    uint16
		answers int
	}{{"cname.test.", dns.TypeA, 2}, {"ipv6.test.", dns.TypeA, 0}, {"ipv6.test.", dns.TypeAAAA, 1}} {
		c, err := transport.DialContext(ctx, "udp", "10.77.0.2:53")
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		q := new(dns.Msg)
		q.SetQuestion(query.name, query.kind)
		raw, _ := q.Pack()
		c.Write(raw)
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
		a := new(dns.Msg)
		if err := a.Unpack(buf[:n]); err != nil || len(a.Answer) != query.answers {
			t.Fatal("fixture DNS answer mismatch", query.name, err)
		}
	}
	if f.vpnTCP.Load() != 2 || f.vpnUDP.Load() != 2 {
		t.Fatal("observer counters do not reflect actual flows")
	}
}

// Unlike hosts-only DNS tests, exercise real upstream UDP resolution through
// AWG, with the same compiled DNS rules and restart as the native hosts.
func TestEngineRealDNSAndPeerRestart(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	f := &fixture{server: server, client: client}
	if err := f.start(); err != nil {
		t.Fatal(err)
	}
	defer f.stop()
	physical, err := net.Listen("tcp4", "127.0.0.1:18081")
	if err != nil {
		t.Fatal(err)
	}
	defer physical.Close()
	go observeTCP(physical, "DIRECT", &f.directTCP)
	for cycle := 0; cycle < 3; cycle++ {
		if cycle > 0 {
			f.stop()
			if err := f.start(); err != nil {
				t.Fatal(err)
			}
		}
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			config := engine.SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN, Rules: []rules.Rule{{Kind: rules.Suffix, Value: "direct.ru", Action: rules.Direct}}},
				Resolver: netip.MustParseAddrPort("10.77.0.2:53"), ResolverAction: rules.VPN,
				AWG: awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("fd77::1")},
					PrivateKey: base64.StdEncoding.EncodeToString(client.Bytes()), PublicKey: base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()),
					Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), f.listenPort), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
					Parameters: map[string]string{"jc": "3", "jmin": "40", "jmax": "80", "s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}}}
			raw, err := config.Compile()
			if err != nil {
				t.Fatal(err)
			}
			var options map[string]any
			if err := json.Unmarshal(raw, &options); err != nil {
				t.Fatal(err)
			}
			options["inbounds"] = []any{}
			raw, err = json.Marshal(options)
			if err != nil {
				t.Fatal(err)
			}
			var lc net.ListenConfig
			ctx = engine.Context(ctx, engine.Underlay{ListenPacket: lc.ListenPacket, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
				destination, _ := netip.ParseAddrPort(a)
				if destination.Addr() == netip.MustParseAddr(sharedIP) {
					a = net.JoinHostPort("127.0.0.1", "18081")
				}
				var d net.Dialer
				return d.DialContext(ctx, n, a)
			}})
			ctx = service.ContextWith[adapter.PlatformInterface](ctx, fixturePlatform{})
			box, err := engine.New(ctx, raw)
			if err != nil {
				t.Fatal(err)
			}
			if err = box.Start(); err != nil {
				t.Fatal(err)
			}
			defer box.Close()
			dr := service.FromContext[adapter.DNSRouter](ctx)
			dm := service.FromContext[adapter.DNSTransportManager](ctx)
			fake, _ := dm.Transport("fake")
			for _, name := range []string{"direct.ru", "vpn.test"} {
				q := new(dns.Msg)
				q.SetQuestion(name+".", dns.TypeA)
				answer, err := dr.Exchange(ctx, q, adapter.DNSQueryOptions{Transport: fake})
				if err != nil {
					t.Fatal(err)
				}
				ip := netip.MustParseAddr(answer.Answer[0].(*dns.A).A.String())
				app, capture := net.Pipe()
				// This is correctness/restart acceptance, not a latency budget.
				// Allow the pinned AWG/TCP retransmission timers on loaded race
				// runners; the separate first-flight UDP burst still has 2s.
				app.SetDeadline(time.Now().Add(10 * time.Second))
				go box.Router().RouteConnectionEx(ctx, capture, adapter.InboundContext{Inbound: engine.TUNTag, Network: "tcp", Destination: M.Socksaddr{Addr: ip, Port: 18081}}, nil)
				reply := make([]byte, 16)
				n, err := app.Read(reply)
				app.Close()
				if err != nil {
					out, _ := box.Outbound().Outbound("vpn")
					stats, _ := out.(*awg.Outbound).Stats()
					t.Fatalf("cycle %d %s: %v, DNS queries %d, VPN accepts %d, AWG counters %+v", cycle, name, err, f.dnsQueries.Load(), f.vpnTCP.Load(), stats)
				}
				want := "VPN\n"
				if name == "direct.ru" {
					want = "DIRECT\n"
				}
				if string(reply[:n]) != want {
					t.Fatalf("cycle %d %s wrong observer: %q", cycle, name, reply[:n])
				}
			}
		}()
	}
}

type fixturePlatform struct{ adapter.PlatformInterface }

func (fixturePlatform) Initialize(adapter.NetworkManager) error  { return nil }
func (fixturePlatform) UsePlatformDefaultInterfaceMonitor() bool { return true }
func (fixturePlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}
func (fixturePlatform) UsePlatformNetworkInterfaces() bool { return true }
func (fixturePlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return []adapter.NetworkInterface{{Interface: control.Interface{Index: 1, Name: "lo", Addresses: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}}}}, nil
}
func (fixturePlatform) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (fixturePlatform) UnderNetworkExtension() bool                 { return false }
func (fixturePlatform) UsePlatformConnectionOwnerFinder() bool      { return false }
