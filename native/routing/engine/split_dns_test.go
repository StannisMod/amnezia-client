package engine

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
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

func TestSplitDNSNamedUpstreamUsesOnlyExplicitBootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var bootstrapQueries, upstreamQueries atomic.Int32
	serve := func(bootstrap bool) (netip.AddrPort, *dns.Server) {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		s := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			r := new(dns.Msg)
			r.SetReply(q)
			name := strings.ToLower(q.Question[0].Name)
			if bootstrap {
				bootstrapQueries.Add(1)
				if name != "resolver.test." {
					t.Errorf("application name leaked to bootstrap: %s", name)
				}
			} else {
				upstreamQueries.Add(1)
				if name == "resolver.test." {
					t.Error("DNS server bootstrapped recursively")
				}
			}
			if q.Question[0].Qtype == dns.TypeA {
				answer := "192.0.2.7"
				if bootstrap {
					answer = "127.0.0.1"
				}
				r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(answer)}}
			}
			w.WriteMsg(r)
		})}
		ready := make(chan struct{})
		s.NotifyStartedFunc = func() { close(ready) }
		go s.ActivateAndServe()
		<-ready
		t.Cleanup(func() { s.Shutdown() })
		return netip.MustParseAddrPort(pc.LocalAddr().String()), s
	}
	bootstrap, _ := serve(true)
	upstream, _ := serve(false)
	priv, pub := keys(t)
	session := SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN}, AWG: awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: priv, PublicKey: pub, Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		DNS: &dnspolicy.Config{Version: 1, Default: "named", Policies: map[string]dnspolicy.Resolver{"named": {Transport: "udp", Server: "resolver.test", Port: upstream.Port(), Path: rules.Direct, Bootstrap: bootstrap}}}}
	raw, err := session.Compile()
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	json.Unmarshal(raw, &config)
	delete(config, "inbounds")
	raw, _ = json.Marshal(config)
	var dial net.Dialer
	var lc net.ListenConfig
	ctx = Context(ctx, Underlay{DialContext: dial.DialContext, ListenPacket: lc.ListenPacket})
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
	instance, err := New(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	query := new(dns.Msg)
	query.SetQuestion("application.test.", dns.TypeA)
	answer, err := service.FromContext[adapter.DNSRouter](ctx).Exchange(ctx, query, adapter.DNSQueryOptions{})
	if err != nil || len(answer.Answer) != 1 || answer.Answer[0].(*dns.A).A.String() != "192.0.2.7" {
		t.Fatal("named DNS upstream failed", err)
	}
	if bootstrapQueries.Load() == 0 || upstreamQueries.Load() != 1 {
		t.Fatal("bootstrap or upstream was bypassed")
	}
}

// Two independently observed DNS servers operate simultaneously. One is
// reachable via protected DIRECT sockets, the other only inside a real AWG
// peer. This tests the production compiler and DNS router, not mocked routing.
func TestSplitDNSSimultaneousPolicies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	aPriv, aPub := keys(t)
	bPriv, bPub := keys(t)
	reserved, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	aPort := uint16(reserved.LocalAddr().(*net.UDPAddr).Port)
	reserved.Close()
	var dial net.Dialer
	var lc net.ListenConfig
	b, err := awg.New(ctx, awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.2")}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), aPort), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")}}, lc.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	bPort, err := b.LocalPort()
	if err != nil {
		t.Fatal(err)
	}
	type observer struct {
		sync.Mutex
		names []string
	}
	var direct, vpn observer
	startDNS := func(pc net.PacketConn, seen *observer, answer string) *dns.Server {
		s := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			seen.Lock()
			seen.names = append(seen.names, strings.ToLower(q.Question[0].Name))
			seen.Unlock()
			r := new(dns.Msg)
			r.SetReply(q)
			name := q.Question[0].Name
			if strings.HasPrefix(name, "missing.") {
				r.Rcode = dns.RcodeNameError
			} else {
				h := dns.RR_Header{Name: name, Rrtype: q.Question[0].Qtype, Class: dns.ClassINET, Ttl: 60}
				switch h.Rrtype {
				case dns.TypeA:
					r.Answer = []dns.RR{&dns.A{Hdr: h, A: net.ParseIP(answer)}}
				case dns.TypeAAAA:
					r.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.ParseIP("2001:db8::7")}}
				case dns.TypeTXT:
					r.Answer = []dns.RR{&dns.TXT{Hdr: h, Txt: []string{answer}}}
				}
			}
			w.WriteMsg(r)
		})}
		ready := make(chan struct{})
		s.NotifyStartedFunc = func() { close(ready) }
		go s.ActivateAndServe()
		<-ready
		t.Cleanup(func() { s.Shutdown() })
		return s
	}
	dpc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	vpc, err := b.Net.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.2:0"))
	if err != nil {
		t.Fatal(err)
	}
	dserver := startDNS(dpc, &direct, "127.0.0.1")
	startDNS(vpc, &vpn, "10.77.0.2")
	policy := &dnspolicy.Config{Version: 1, Default: "vpn", FollowRouting: true, Direct: "lan", VPN: "vpn",
		Policies: map[string]dnspolicy.Resolver{
			"lan": {Transport: "udp", Server: "127.0.0.1", Port: uint16(dpc.LocalAddr().(*net.UDPAddr).Port), Path: rules.Direct},
			"vpn": {Transport: "udp", Server: "10.77.0.2", Port: netip.MustParseAddrPort(vpc.LocalAddr().String()).Port(), Path: rules.VPN}},
		Rules: []dnspolicy.Rule{{Kind: rules.Suffix, Value: "*.corp.example", Policy: "lan"}, {Kind: rules.Domain, Value: "public.corp.example", Policy: "vpn"}}}
	session := SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN, Rules: []rules.Rule{{Kind: rules.Suffix, Value: "*.direct.test", Action: rules.Direct}, {Kind: rules.Suffix, Value: "*.corp.example", Action: rules.Direct}}},
		AWG: awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: aPriv, PublicKey: bPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), bPort), ListenPort: aPort, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}, DNS: policy}
	raw, err := session.Compile()
	if err != nil {
		t.Fatal(err)
	}
	var compiled map[string]any
	json.Unmarshal(raw, &compiled)
	delete(compiled, "inbounds")
	raw, _ = json.Marshal(compiled)
	ctx = Context(ctx, Underlay{DialContext: dial.DialContext, ListenPacket: lc.ListenPacket})
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
	instance, err := New(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	router := service.FromContext[adapter.DNSRouter](ctx)
	exchange := func(name string, kind uint16, captured bool) *dns.Msg {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), kind)
		queryCtx := ctx
		if captured {
			queryCtx = adapter.WithContext(ctx, &adapter.InboundContext{Inbound: TUNTag})
		}
		r, err := router.Exchange(queryCtx, q, adapter.DNSQueryOptions{})
		if err != nil {
			t.Fatal(name, err)
		}
		return r
	}
	for _, test := range []struct{ name, want string }{
		{"Host.Corp.Example.", "127.0.0.1"}, {"corp.example", "127.0.0.1"}, {"nested.corp.example", "127.0.0.1"},
		{"public.corp.example", "10.77.0.2"}, {"evilcorp.example", "10.77.0.2"}, {"site.direct.test", "127.0.0.1"}, {"ordinary.test", "10.77.0.2"},
	} {
		for i := 0; i < 2; i++ {
			r := exchange(test.name, dns.TypeA, false)
			if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != test.want {
				t.Fatalf("%s: %#v", test.name, r)
			}
		}
	}
	for _, name := range []string{"_service._tcp.corp.example", "_service._tcp.ordinary.test"} {
		r := exchange(name, dns.TypeTXT, true)
		if len(r.Answer) != 1 {
			t.Fatal("non-address query lost DNS policy")
		}
	}
	if exchange("missing.corp.example", dns.TypeTXT, true).Rcode != dns.RcodeNameError {
		t.Fatal("lost NXDOMAIN")
	}
	if len(exchange("v6.corp.example", dns.TypeAAAA, false).Answer) != 1 {
		t.Fatal("lost AAAA")
	}
	// FakeIP must defer upstream DNS until a real connection needs an address.
	count := func(o *observer) int { o.Lock(); defer o.Unlock(); return len(o.names) }
	for _, test := range []struct {
		name, marker string
		vpn          bool
	}{{"flow.corp.example", "DIRECT", false}, {"flow.ordinary.test", "TUNNEL", true}} {
		var listener net.Listener
		if test.vpn {
			listener, err = b.Net.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.2:0"))
		} else {
			listener, err = net.Listen("tcp4", "127.0.0.1:0")
		}
		if err != nil {
			t.Fatal(err)
		}
		go func(l net.Listener, marker string) {
			c, e := l.Accept()
			if e == nil {
				defer c.Close()
				io.WriteString(c, marker)
			}
		}(listener, test.marker)
		before := count(&direct) + count(&vpn)
		r := exchange(test.name, dns.TypeA, true)
		if count(&direct)+count(&vpn) != before {
			t.Fatal("FakeIP queried upstream eagerly")
		}
		ip := netip.MustParseAddr(r.Answer[0].(*dns.A).A.String())
		port := netip.MustParseAddrPort(listener.Addr().String()).Port()
		app, capture := net.Pipe()
		app.SetDeadline(time.Now().Add(5 * time.Second))
		go instance.Router().RouteConnectionEx(ctx, capture, adapter.InboundContext{Inbound: TUNTag, Network: "tcp", Destination: M.Socksaddr{Addr: ip, Port: port}}, nil)
		buffer := make([]byte, len(test.marker))
		_, err = io.ReadFull(app, buffer)
		app.Close()
		listener.Close()
		if err != nil || string(buffer) != test.marker {
			t.Fatalf("FakeIP %s: %q %v", test.name, buffer, err)
		}
	}
	assertIsolation := func() {
		t.Helper()
		for _, entry := range []struct {
			o      *observer
			direct bool
		}{{&direct, true}, {&vpn, false}} {
			entry.o.Lock()
			names := append([]string(nil), entry.o.names...)
			entry.o.Unlock()
			for _, name := range names {
				wantDirect := (name == "corp.example." || strings.HasSuffix(name, ".corp.example.") || strings.HasSuffix(name, ".direct.test.")) && name != "public.corp.example."
				if wantDirect != entry.direct {
					t.Fatalf("cross-policy DNS leak: %s on direct=%v", name, entry.direct)
				}
			}
		}
	}
	assertIsolation()
	// A stopped direct DNS must not fall back to the still-working VPN DNS.
	dserver.Shutdown()
	beforeVPN := count(&vpn)
	failureCtx, stop := context.WithTimeout(ctx, 150*time.Millisecond)
	defer stop()
	q := new(dns.Msg)
	q.SetQuestion("unavailable.corp.example.", dns.TypeTXT)
	if _, err = router.Exchange(failureCtx, q, adapter.DNSQueryOptions{}); err == nil {
		t.Fatal("unavailable DIRECT DNS succeeded")
	}
	if count(&vpn) != beforeVPN {
		t.Fatal("DIRECT DNS failure leaked to VPN")
	}
	// VPN death must not put private VPN-selected names on DIRECT DNS.
	b.Close()
	beforeDirect := count(&direct)
	failureCtx2, stop2 := context.WithTimeout(ctx, 150*time.Millisecond)
	defer stop2()
	q.SetQuestion("unavailable.ordinary.test.", dns.TypeTXT)
	if _, err = router.Exchange(failureCtx2, q, adapter.DNSQueryOptions{}); err == nil {
		t.Fatal("unavailable VPN DNS succeeded")
	}
	if count(&direct) != beforeDirect {
		t.Fatal("VPN DNS failure leaked to DIRECT")
	}
}
