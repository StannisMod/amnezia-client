//go:build linux && !android

package desktop

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/miekg/dns"
)

func TestEndpointDiscoveryUsesProtectedDialerAndOnlyQuestionOwners(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "endpoint.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "actual.test."},
			&dns.A{Hdr: dns.RR_Header{Name: "unrelated.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.99")}}
		if q.Question[0].Qtype == dns.TypeA {
			r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: "actual.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.8")})
		} else {
			r.Answer = append(r.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: "actual.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:db8::8")})
		}
		w.WriteMsg(r)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go server.ActivateAndServe()
	<-ready
	defer server.Shutdown()
	var calls atomic.Int32
	var dialer net.Dialer
	resolver := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	underlay := engine.Underlay{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != resolver.String() {
			t.Error("DNS escaped the explicitly selected control resolver")
		}
		calls.Add(1)
		return dialer.DialContext(ctx, network, address)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	answers, err := lookupEndpoint(ctx, "endpoint.test", underlay, resolver)
	if err != nil || len(answers) != 2 || answers[0] != netip.MustParseAddr("192.0.2.8") || answers[1] != netip.MustParseAddr("2001:db8::8") || calls.Load() != 2 {
		t.Fatal("incorrect protected endpoint lookup", answers, err, calls.Load())
	}
	before := calls.Load()
	for _, host := range []string{"127.0.0.1", "bad/name", "Endpoint.TEST", "endpoint.test:123"} {
		if _, err = lookupEndpoint(ctx, host, underlay, resolver); err == nil {
			t.Fatal("invalid endpoint hostname accepted", host)
		}
	}
	if calls.Load() != before {
		t.Fatal("invalid hostname reached DNS")
	}
}
func TestEndpointDiscoveryHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	host := engine.Underlay{DialContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) { calls.Add(1); return nil, ctx.Err() }}
	if result, err := lookupEndpoint(ctx, "endpoint.test", host, netip.MustParseAddrPort("127.0.0.1:53")); err == nil || len(result) != 0 {
		t.Fatal("cancelled discovery returned candidates")
	}
}

func TestEndpointDiscoveryRetriesOnlyTheSameResolverOverTCP(t *testing.T) {
	for _, drop := range []bool{false, true} {
		name := "truncated"
		if drop {
			name = "UDP-blocked"
		}
		t.Run(name, func(t *testing.T) {
			listener, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			resolver := listener.Addr().(*net.TCPAddr).AddrPort()
			packet, e := net.ListenPacket("udp4", resolver.String())
			if e != nil {
				listener.Close()
				t.Fatal(e)
			}
			var tcpCalls atomic.Int32
			udp := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				if drop {
					return
				}
				r := new(dns.Msg)
				r.SetReply(q)
				r.Truncated = true
				w.WriteMsg(r)
			})}
			tcp := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				tcpCalls.Add(1)
				r := new(dns.Msg)
				r.SetReply(q)
				if q.Question[0].Qtype == dns.TypeA {
					r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.8")}}
				}
				w.WriteMsg(r)
			})}
			for _, s := range []*dns.Server{udp, tcp} {
				ready := make(chan struct{})
				s.NotifyStartedFunc = func() { close(ready) }
				go s.ActivateAndServe()
				<-ready
				t.Cleanup(func() { s.Shutdown() })
			}
			var dialer net.Dialer
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			result, e := lookupEndpoint(ctx, "endpoint.test", engine.Underlay{DialContext: func(ctx context.Context, n, address string) (net.Conn, error) {
				if address != resolver.String() {
					t.Error("endpoint DNS fell back to another destination")
				}
				return dialer.DialContext(ctx, n, address)
			}}, resolver)
			if e != nil || len(result) != 1 || result[0] != netip.MustParseAddr("192.0.2.8") || tcpCalls.Load() != 2 {
				t.Fatal("bounded TCP control-DNS retry failed", result, e, tcpCalls.Load())
			}
		})
	}
}
