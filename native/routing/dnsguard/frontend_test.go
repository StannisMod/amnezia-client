package dnsguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/miekg/dns"
)

func pair(t *testing.T, ipv6 bool, exchange Exchange) (*Frontend, *awg.FlowStack) {
	return pairContext(t, context.Background(), ipv6, exchange)
}

func pairContext(t *testing.T, parent context.Context, ipv6 bool, exchange Exchange) (*Frontend, *awg.FlowStack) {
	t.Helper()
	local, remote := "172.19.0.2", "10.77.0.2"
	if ipv6 {
		local, remote = "fd19::2", "fd77::2"
	}
	front, err := New(parent, netip.MustParseAddr(local), exchange)
	if err != nil {
		t.Fatal(err)
	}
	peer, stack, err := awg.NewFlowTUN([]netip.Addr{netip.MustParseAddr(remote)}, 1280)
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	done := make(chan struct{}, 2)
	pump := func(from, to tun.Device) {
		defer func() { done <- struct{}{} }()
		data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
		for {
			n, err := from.Read(data, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 {
				if _, err := to.Write([][]byte{data[0][:sizes[0]]}, 0); err != nil {
					return
				}
			}
		}
	}
	go pump(peer, front.Device())
	go pump(front.Device(), peer)
	t.Cleanup(func() {
		front.Close()
		peer.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("DNS packet pump did not stop")
			}
		}
	})
	return front, stack
}

func query(t *testing.T, stack *awg.FlowStack, ipv6 bool, transport string, qtype uint16) *dns.Msg {
	t.Helper()
	target := "172.19.0.2:53"
	if ipv6 {
		target = "[fd19::2]:53"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := stack.DialContext(ctx, transport, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	q := new(dns.Msg)
	q.SetQuestion("managed.example.", qtype)
	q.AuthenticatedData = true
	q.SetEdns0(1232, true)
	answer, _, err := (&dns.Client{Net: transport}).ExchangeWithConn(q, &dns.Conn{Conn: conn})
	if err != nil {
		t.Fatal(err)
	}
	if answer.Id != q.Id || !answer.Response {
		t.Fatal("DNS response lost request identity")
	}
	return answer
}

func TestNativeDNSFrontendUDPAndTCPNODATAWithoutUpstream(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, transport := range []string{"udp", "tcp"} {
			t.Run(net.JoinHostPort(map[bool]string{false: "v4", true: "v6"}[ipv6], transport), func(t *testing.T) {
				var forwarded atomic.Int32
				_, stack := pair(t, ipv6, func(_ context.Context, network string, request *dns.Msg) (*dns.Msg, error) {
					if network != transport {
						return nil, errors.New("DNS transport changed")
					}
					forwarded.Add(1)
					answer := new(dns.Msg).SetReply(request)
					rr, err := dns.NewRR("managed.example. 60 IN A 198.51.100.2")
					if err != nil {
						return nil, err
					}
					answer.Answer = []dns.RR{rr}
					return answer, nil
				})
				answer := query(t, stack, ipv6, transport, dns.TypeAAAA)
				if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 || answer.AuthenticatedData || forwarded.Load() != 0 {
					t.Fatal("AAAA policy was forwarded, authenticated, or not NODATA")
				}
				answer = query(t, stack, ipv6, transport, dns.TypeA)
				if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 || forwarded.Load() != 1 {
					t.Fatal("IPv4 DNS was not forwarded to its explicit scope")
				}
			})
		}
	}
}

func TestNativeDNSFrontendDoesNotFallbackOnUpstreamFailure(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			_, stack := pair(t, false, func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
				return nil, errors.New("selected DNS path unavailable")
			})
			if answer := query(t, stack, false, transport, dns.TypeA); answer.Rcode != dns.RcodeServerFailure {
				t.Fatal("unavailable selected DNS path did not fail closed")
			}
		})
	}
}

func TestNativeDNSFrontendRequiresExplicitScope(t *testing.T) {
	if frontend, err := New(context.Background(), netip.MustParseAddr("172.19.0.2"), nil); err == nil {
		frontend.Close()
		t.Fatal("DNS frontend accepted implicit/default upstream")
	}
}

func TestNativeDNSFrontendCancellationStopsPendingExchange(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			started, released := make(chan struct{}), make(chan struct{})
			front, stack := pairContext(t, parent, false, func(ctx context.Context, _ string, _ *dns.Msg) (*dns.Msg, error) {
				close(started)
				<-ctx.Done()
				close(released)
				return nil, ctx.Err()
			})
			conn, err := stack.DialContext(parent, transport, "172.19.0.2:53")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			queryDone := make(chan struct{})
			go func() {
				defer close(queryDone)
				q := new(dns.Msg).SetQuestion("pending.example.", dns.TypeA)
				_, _, _ = (&dns.Client{Net: transport}).ExchangeWithConn(q, &dns.Conn{Conn: conn})
			}()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("scoped exchange never started")
			}
			cancel()
			select {
			case <-released:
			case <-time.After(time.Second):
				t.Fatal("parent cancellation did not reach the scoped exchange")
			}
			closeDone := make(chan struct{})
			go func() { _ = front.Close(); close(closeDone) }()
			select {
			case <-closeDone:
			case <-time.After(3 * time.Second):
				t.Fatal("frontend shutdown stalled with a pending query")
			}
			conn.Close()
			select {
			case <-queryDone:
			case <-time.After(time.Second):
				t.Fatal("client query did not finish after close")
			}
		})
	}
}
