package engine

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

func TestManagedDNSUpstreamCNAMECacheAndFakeIP(t *testing.T) {
	pc, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var requests atomic.Int32
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		requests.Add(1)
		r := new(dns.Msg)
		r.SetReply(q)
		switch q.Question[0].Qtype {
		case dns.TypeA:
			r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "target.test."}, &dns.A{Hdr: dns.RR_Header{Name: "target.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.7")}}
		case dns.TypeAAAA:
			r.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::7")}}
		}
		w.WriteMsg(r)
	})}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go server.ActivateAndServe()
	<-started
	defer server.Shutdown()
	priv, pub := keys(t)
	raw, e := (SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN}, AWG: awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: priv, PublicKey: pub, Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}, Resolver: netip.MustParseAddrPort(pc.LocalAddr().String()), ResolverAction: rules.Direct}).Compile()
	if e != nil {
		t.Fatal(e)
	}
	// Exercise the same DNS compiler without starting an OS capture TUN.
	var config map[string]any
	json.Unmarshal(raw, &config)
	delete(config, "inbounds")
	raw, _ = json.Marshal(config)
	var dial net.Dialer
	var lc net.ListenConfig
	ctx := Context(context.Background(), Underlay{DialContext: dial.DialContext, ListenPacket: lc.ListenPacket})
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
	instance, e := New(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = instance.Start(); e != nil {
		t.Fatal(e)
	}
	defer instance.Close()
	router := service.FromContext[adapter.DNSRouter](ctx)
	manager := service.FromContext[adapter.DNSTransportManager](ctx)
	upstream, _ := manager.Transport("upstream")
	query := new(dns.Msg)
	query.SetQuestion("alias.test.", dns.TypeA)
	for i := 0; i < 2; i++ {
		answer, e := router.Exchange(ctx, query, adapter.DNSQueryOptions{Transport: upstream})
		if e != nil {
			t.Fatal(e)
		}
		if len(answer.Answer) != 2 || answer.Answer[1].(*dns.A).A.String() != "192.0.2.7" {
			t.Fatal("lost CNAME/A response")
		}
	}
	if requests.Load() != 1 {
		t.Fatal("DNS response was not cached")
	}
	router.ClearCache()
	if _, e = router.Exchange(ctx, query, adapter.DNSQueryOptions{Transport: upstream}); e != nil {
		t.Fatal(e)
	}
	if requests.Load() != 2 {
		t.Fatal("DNS clear did not invalidate cache")
	}
	query.SetQuestion("target.test.", dns.TypeAAAA)
	answer, e := router.Exchange(ctx, query, adapter.DNSQueryOptions{Transport: upstream})
	if e != nil {
		t.Fatal(e)
	}
	if answer.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::7" {
		t.Fatal("lost AAAA response")
	}
	before := requests.Load()
	captureCtx := adapter.WithContext(ctx, &adapter.InboundContext{Inbound: TUNTag})
	query.SetQuestion("alias.test.", dns.TypeA)
	fake, e := router.Exchange(captureCtx, query, adapter.DNSQueryOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if !netip.MustParsePrefix("198.18.0.0/15").Contains(netip.MustParseAddr(fake.Answer[0].(*dns.A).A.String())) {
		t.Fatal("capture query did not get FakeIP")
	}
	if requests.Load() != before {
		t.Fatal("FakeIP query escaped to upstream")
	}
}
