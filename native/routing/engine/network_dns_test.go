package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type dnsTestLifetime struct{ closed atomic.Bool }

func (l *dnsTestLifetime) Close() error { l.closed.Store(true); return nil }

type delayedGenerationRouter struct {
	adapter.DNSRouter
	started, release chan struct{}
}

func (r *delayedGenerationRouter) Exchange(context.Context, *dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error) {
	close(r.started)
	<-r.release
	return new(dns.Msg), nil
}

func TestLateNetworkDNSCannotEscapeGenerationBoundary(t *testing.T) {
	p := &networkDNSProxy{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	life := &dnsTestLifetime{}
	router := &delayedGenerationRouter{started: make(chan struct{}), release: make(chan struct{})}
	g := &dnsGeneration{box: life, router: router, ctx: ctx, cancel: cancel, stopParent: func() bool { return true }}
	if !p.replace(g, 0) {
		t.Fatal("initial generation rejected")
	}
	done := make(chan error, 1)
	go func() {
		response, err := p.exchange(context.Background(), new(dns.Msg))
		if response != nil {
			done <- errors.New("retired DNS response escaped")
			return
		}
		done <- err
	}()
	<-router.started
	version := p.freeze()
	if !life.closed.Load() {
		t.Fatal("old DNS resources retained")
	}
	// Resolver deliberately ignores cancellation and returns after retirement.
	close(router.release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("late response accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("query leaked")
	}
	otherCtx, otherCancel := context.WithCancel(context.Background())
	defer otherCancel()
	otherLife := &dnsTestLifetime{}
	stale := &dnsGeneration{box: otherLife, ctx: otherCtx, cancel: otherCancel, stopParent: func() bool { return true }}
	p.freeze() // Another native network change while a candidate was building.
	if p.replace(stale, version) || !otherLife.closed.Load() {
		t.Fatal("stale DNS build revived retired network")
	}
}

func TestNetworkDNSGenerationDoesNotOwnApplicationTCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	serveDNS := func(pc net.PacketConn, answer string) (uint16, *atomic.Int32) {
		count := new(atomic.Int32)
		s := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			count.Add(1)
			r := new(dns.Msg)
			r.SetReply(q)
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(answer)}}
			w.WriteMsg(r)
		})}
		ready := make(chan struct{})
		s.NotifyStartedFunc = func() { close(ready) }
		go s.ActivateAndServe()
		<-ready
		t.Cleanup(func() { s.Shutdown() })
		return uint16(pc.LocalAddr().(*net.UDPAddr).Port), count
	}
	startDNS := func(answer string) (uint16, *atomic.Int32) {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return serveDNS(pc, answer)
	}
	firstPort, firstQueries := startDNS("192.0.2.11")
	secondPort, secondQueries := startDNS("192.0.2.12")
	aPriv, aPub := keys(t)
	bPriv, bPub := keys(t)
	clientPort, listen := reserveTestUnderlay(t)
	peer, err := awg.New(ctx, awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.2")}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), clientPort), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")}}, listen)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerPort, err := peer.LocalPort()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := peer.Net.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.2:19081"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepts atomic.Int32
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			accepts.Add(1)
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	pc, err := peer.Net.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.2:0"))
	if err != nil {
		t.Fatal(err)
	}
	vpnPort, vpnQueries := serveDNS(pc, "192.0.2.13")
	interfaceName := "net-a"
	useVPN := false
	transport := "udp"
	compile := func(port uint16) []byte {
		cfg := SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN}, AWG: awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: aPriv, PublicKey: bPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), peerPort), ListenPort: clientPort, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}, DNS: &dnspolicy.Config{Version: 1, Default: "lan", Policies: map[string]dnspolicy.Resolver{"lan": {Transport: transport, Server: "127.0.0.1", Port: port, Path: rules.Direct, Interface: interfaceName}}}}
		if useVPN {
			cfg.DNS.Policies["tunnel"] = dnspolicy.Resolver{Transport: "udp", Server: "10.77.0.2", Port: vpnPort, Path: rules.VPN}
			cfg.DNS.Rules = []dnspolicy.Rule{{Kind: rules.Domain, Value: "cache.test", Policy: "tunnel"}}
		}
		raw, e := cfg.Compile()
		if e != nil {
			t.Fatal(e)
		}
		var options map[string]any
		json.Unmarshal(raw, &options)
		delete(options, "inbounds")
		raw, _ = json.Marshal(options)
		return raw
	}
	var dial net.Dialer
	var aQueries, bQueries atomic.Int32
	ctx = Context(ctx, Underlay{ListenPacket: listen, DialContext: dial.DialContext, OnInterface: func(name string) (Underlay, error) {
		var counter *atomic.Int32
		switch name {
		case "net-a":
			counter = &aQueries
		case "net-b":
			counter = &bQueries
		default:
			return Underlay{}, errors.New("unavailable test interface")
		}
		return Underlay{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			counter.Add(1)
			return dial.DialContext(ctx, network, address)
		}, ListenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			counter.Add(1)
			var lc net.ListenConfig
			return lc.ListenPacket(ctx, network, address)
		}}, nil
	}})
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
	runtime, err := StartRuntimeWithNetworkDNS(ctx, compile(firstPort), "")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	app, router := net.Pipe()
	defer app.Close()
	go runtime.box.Router().RouteConnectionEx(ctx, router, adapter.InboundContext{Inbound: TUNTag, Network: "tcp", Source: M.ParseSocksaddr("127.0.0.1:12345"), Destination: M.ParseSocksaddr("10.77.0.2:19081")}, nil)
	app.SetDeadline(time.Now().Add(10 * time.Second))
	exchange := func(data string) {
		t.Helper()
		if _, e := io.WriteString(app, data); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, len(data))
		if _, e := io.ReadFull(app, got); e != nil || string(got) != data {
			t.Fatal("existing app TCP failed", e)
		}
		if accepts.Load() != 1 {
			t.Fatal("DNS reload replaced TCP")
		}
	}
	exchange("before DNS update")
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	query := new(dns.Msg)
	query.SetQuestion("cache.test.", dns.TypeA)
	lookup := func() string {
		t.Helper()
		r, e := dnsRouter.Exchange(ctx, query, adapter.DNSQueryOptions{})
		if e != nil {
			t.Fatal(e)
		}
		return r.Answer[0].(*dns.A).A.String()
	}
	if lookup() != "192.0.2.11" || lookup() != "192.0.2.11" || firstQueries.Load() != 1 {
		t.Fatal("generation cache unavailable")
	}
	manager := service.FromContext[adapter.DNSTransportManager](ctx)
	fake, _ := manager.Transport("fake")
	fakeBefore, err := dnsRouter.Exchange(ctx, query, adapter.DNSQueryOptions{Transport: fake})
	if err != nil {
		t.Fatal(err)
	}
	runtime.SuspendNetworkDNS()
	if _, err = dnsRouter.Exchange(ctx, query, adapter.DNSQueryOptions{}); err == nil {
		t.Fatal("outer cache bypassed suspended generation")
	}
	exchange("while DNS is unavailable")
	if runtime.ReloadNetworkDNS([]byte(`{}`)) == nil {
		t.Fatal("invalid DNS candidate accepted")
	}
	if _, err = dnsRouter.Exchange(ctx, query, adapter.DNSQueryOptions{}); err == nil {
		t.Fatal("invalid snapshot revived old DNS")
	}
	exchange("after failed DNS update")
	interfaceName = "net-b"
	if err = runtime.ReloadNetworkDNS(compile(secondPort)); err != nil {
		t.Fatal(err)
	}
	if lookup() != "192.0.2.12" || secondQueries.Load() != 1 || firstQueries.Load() != 1 {
		t.Fatal("old DNS answer/path survived reload")
	}
	if aQueries.Load() != 1 || bQueries.Load() != 1 {
		t.Fatal("DNS did not replace interface binding", aQueries.Load(), bQueries.Load())
	}
	useVPN = true
	if err = runtime.ReloadNetworkDNS(compile(secondPort)); err != nil {
		t.Fatal(err)
	}
	if lookup() != "192.0.2.13" || vpnQueries.Load() != 1 || secondQueries.Load() != 1 || firstQueries.Load() != 1 {
		t.Fatal("changed DNS domain rule used stale DIRECT path/cache")
	}
	exchange("after DNS policy moves to existing VPN")
	useVPN = false
	if err = runtime.ReloadNetworkDNS(compile(secondPort)); err != nil {
		t.Fatal(err)
	}
	if lookup() != "192.0.2.12" || secondQueries.Load() != 2 || vpnQueries.Load() != 1 {
		t.Fatal("DNS did not move back to DIRECT")
	}
	transport = "tls"
	if err = runtime.ReloadNetworkDNS(compile(secondPort)); err != nil {
		t.Fatal(err)
	}
	limited, stopLookup := context.WithTimeout(ctx, 200*time.Millisecond)
	_, err = dnsRouter.Exchange(limited, query, adapter.DNSQueryOptions{})
	stopLookup()
	if err == nil || secondQueries.Load() != 2 || vpnQueries.Load() != 1 {
		t.Fatal("encrypted DNS failed open to plaintext/another path")
	}
	exchange("while encrypted DNS is unreachable")
	transport = "udp"
	if err = runtime.UpdateNetworkDNS(func() ([]byte, error) {
		candidate := compile(secondPort)
		runtime.SuspendNetworkDNS() // Native change during preparation.
		return candidate, nil
	}); err == nil {
		t.Fatal("superseded preparation was published")
	}
	if _, err = dnsRouter.Exchange(ctx, query, adapter.DNSQueryOptions{}); err == nil {
		t.Fatal("superseded preparation revived DNS")
	}
	exchange("after a superseded DNS preparation")
	if err = runtime.ReloadNetworkDNS(compile(secondPort)); err != nil {
		t.Fatal(err)
	}
	fakeAfter, err := dnsRouter.Exchange(ctx, query, adapter.DNSQueryOptions{Transport: fake})
	if err != nil {
		t.Fatal(err)
	}
	if fakeBefore.Answer[0].String() != fakeAfter.Answer[0].String() {
		t.Fatal("DNS reload changed FakeIP identity")
	}
	exchange("after DNS generation swap")
}
