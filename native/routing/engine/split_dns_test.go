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
	box "github.com/sagernet/sing-box"
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
	testSplitDNSSimultaneousPolicies(t, false)
}

func TestAndroidApplicationDNSContexts(t *testing.T) {
	testSplitDNSSimultaneousPolicies(t, true)
}

func TestLiveAndroidApplicationPolicyPreservesTCP(t *testing.T) {
	testSplitDNSSimultaneousPolicies(t, true, true)
}

func testSplitDNSSimultaneousPolicies(t *testing.T, androidApps bool, liveMode ...bool) {
	live := len(liveMode) != 0 && liveMode[0]
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	aPriv, aPub := keys(t)
	bPriv, bPub := keys(t)
	aPort, listen := reserveTestUnderlay(t)
	var dial net.Dialer
	b, err := awg.New(ctx, awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.2")}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), aPort), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")}}, listen)
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
	if androidApps {
		session.AndroidApplications = &AndroidApplications{SiteRulesUIDs: []uint32{10282}, Live: live}
	}
	raw, err := session.Compile()
	if err != nil {
		t.Fatal(err)
	}
	var compiled map[string]any
	json.Unmarshal(raw, &compiled)
	delete(compiled, "inbounds")
	raw, _ = json.Marshal(compiled)
	ctx = Context(ctx, Underlay{DialContext: dial.DialContext, ListenPacket: listen})
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
	var instance *box.Box
	var applicationRuntime *Runtime
	if androidApps {
		runtime, startErr := StartRuntimeWithNetworkDNS(ctx, raw, "")
		if startErr != nil {
			t.Fatal(startErr)
		}
		defer runtime.Close()
		applicationRuntime = runtime
		instance = runtime.box
	} else {
		instance, err = New(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err = instance.Start(); err != nil {
			t.Fatal(err)
		}
		defer instance.Close()
	}
	router := service.FromContext[adapter.DNSRouter](ctx)
	if androidApps {
		// Resolve the identical name alternately for both application modes.
		// A warm DIRECT cache must never answer the always-VPN lookup.
		for _, kind := range []uint16{dns.TypeA, dns.TypeTXT} {
			for _, uid := range []int32{10282, 10281, 10282, 10281, -1} {
				metadata := &adapter.InboundContext{}
				if uid >= 0 {
					metadata.ProcessInfo = &adapter.ConnectionOwner{UserId: uid}
				}
				q := new(dns.Msg)
				q.SetQuestion("same.corp.example.", kind)
				answer, err := router.Exchange(adapter.WithContext(ctx, metadata), q, adapter.DNSQueryOptions{})
				if err != nil || len(answer.Answer) != 1 {
					t.Fatal(uid, kind, answer, err)
				}
				want := "10.77.0.2"
				if uid == 10282 {
					want = "127.0.0.1"
				}
				var got string
				if kind == dns.TypeA {
					got = answer.Answer[0].(*dns.A).A.String()
				} else {
					got = answer.Answer[0].(*dns.TXT).Txt[0]
				}
				if got != want {
					t.Fatalf("UID %d query %d: got %s want %s", uid, kind, got, want)
				}
			}
		}
		directListener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer directListener.Close()
		port := netip.MustParseAddrPort(directListener.Addr().String()).Port()
		vpnListener, err := b.Net.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.77.0.2"), port))
		if err != nil {
			t.Fatal(err)
		}
		defer vpnListener.Close()
		for label, listener := range map[string]net.Listener{"DIRECT": directListener, "TUNNEL": vpnListener} {
			go func(l net.Listener, marker string) {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					go func(conn net.Conn) {
						defer conn.Close()
						io.WriteString(conn, marker)
						if live {
							io.Copy(conn, conn)
						}
					}(c)
				}
			}(listener, label)
		}
		q := new(dns.Msg)
		q.SetQuestion("flow.corp.example.", dns.TypeA)
		fakeAnswer, err := router.Exchange(adapter.WithContext(ctx, &adapter.InboundContext{Inbound: TUNTag}), q, adapter.DNSQueryOptions{})
		if err != nil {
			t.Fatal(err)
		}
		ip := netip.MustParseAddr(fakeAnswer.Answer[0].(*dns.A).A.String())
		for _, uid := range []int32{10282, 10281, 10282, 10281, -1} {
			metadata := adapter.InboundContext{Inbound: TUNTag, Network: "tcp", Destination: M.Socksaddr{Addr: ip, Port: port}}
			if uid >= 0 {
				metadata.ProcessInfo = &adapter.ConnectionOwner{UserId: uid}
			}
			app, capture := net.Pipe()
			app.SetDeadline(time.Now().Add(5 * time.Second))
			go instance.Router().RouteConnectionEx(ctx, capture, metadata, nil)
			want := "TUNNEL"
			if uid == 10282 {
				want = "DIRECT"
			}
			label := make([]byte, len(want))
			_, err := io.ReadFull(app, label)
			app.Close()
			if err != nil || string(label) != want {
				t.Fatalf("shared FakeIP UID %d: got %q want %s: %v", uid, label, want, err)
			}
		}
		if live {
			openFlow := func(uid int32, want string) net.Conn {
				t.Helper()
				app, capture := net.Pipe()
				app.SetDeadline(time.Now().Add(5 * time.Second))
				metadata := adapter.InboundContext{Inbound: TUNTag, Network: "tcp", Destination: M.Socksaddr{Addr: ip, Port: port}, ProcessInfo: &adapter.ConnectionOwner{UserId: uid}}
				go instance.Router().RouteConnectionEx(ctx, capture, metadata, nil)
				label := make([]byte, len(want))
				if _, err := io.ReadFull(app, label); err != nil || string(label) != want {
					app.Close()
					t.Fatalf("UID%d got %q want%s: %v", uid, label, want, err)
				}
				return app
			}
			oldA, oldB := openFlow(10281, "TUNNEL"), openFlow(10282, "DIRECT")
			defer oldA.Close()
			defer oldB.Close()
			update := func() error {
				next, err := session.Compile()
				if err != nil {
					return err
				}
				var config map[string]any
				if err = json.Unmarshal(next, &config); err != nil {
					return err
				}
				delete(config, "inbounds")
				next, err = json.Marshal(config)
				if err != nil {
					return err
				}
				return applicationRuntime.UpdateAndroidApplications(next)
			}
			session.AndroidApplications.SiteRulesUIDs = []uint32{10281}
			if err := update(); err != nil {
				t.Fatal(err)
			}
			for _, conn := range []net.Conn{oldA, oldB} {
				payload := []byte("original TCP survived policy update")
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != string(payload) {
					t.Fatal("old TCP changed", err)
				}
			}
			openFlow(10281, "DIRECT").Close()
			openFlow(10282, "TUNNEL").Close()
			for _, kind := range []uint16{dns.TypeA, dns.TypeTXT} {
				for _, uid := range []int32{10281, 10282} {
					q := new(dns.Msg)
					q.SetQuestion("same.corp.example.", kind)
					answer, err := router.Exchange(adapter.WithContext(ctx, &adapter.InboundContext{ProcessInfo: &adapter.ConnectionOwner{UserId: uid}}), q, adapter.DNSQueryOptions{})
					if err != nil || len(answer.Answer) != 1 {
						t.Fatal("updated DNS", uid, err)
					}
					want := "10.77.0.2"
					if uid == 10281 {
						want = "127.0.0.1"
					}
					got := ""
					if kind == dns.TypeA {
						got = answer.Answer[0].(*dns.A).A.String()
					} else {
						got = answer.Answer[0].(*dns.TXT).Txt[0]
					}
					if got != want {
						t.Fatalf("old DNS policy/cache survived update: uid%d got%s want%s", uid, got, want)
					}
				}
			}
			session.Rules.Default = rules.Direct
			if err := update(); err == nil {
				t.Fatal("live application update changed destination routing")
			}
			openFlow(10281, "DIRECT").Close()
			openFlow(10282, "TUNNEL").Close()
			if err := applicationRuntime.ReloadNetworkDNS(raw); err == nil {
				t.Fatal("stale network reload reverted application DNS policy")
			}
			session.Rules.Default = rules.VPN
			next, err := session.Compile()
			if err != nil {
				t.Fatal(err)
			}
			var fresh map[string]any
			json.Unmarshal(next, &fresh)
			delete(fresh, "inbounds")
			next, _ = json.Marshal(fresh)
			if err := applicationRuntime.ReloadNetworkDNS(next); err != nil {
				t.Fatal("current policy failed network reload", err)
			}
			openFlow(10281, "DIRECT").Close()
			openFlow(10282, "TUNNEL").Close()
		}
		return
	}
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
