package nativedns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func resolverServer(t *testing.T, network string, handler dns.HandlerFunc) netip.AddrPort {
	t.Helper()
	server := &dns.Server{Handler: handler}
	var address net.Addr
	var err error
	if network == "udp" {
		server.PacketConn, err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err == nil {
			address = server.PacketConn.LocalAddr()
		}
	} else {
		server.Listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err == nil {
			address = server.Listener.Addr()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal("resolver did not start", err)
	case <-time.After(time.Second):
		t.Fatal("resolver startup timeout")
	}
	t.Cleanup(func() { _ = server.Shutdown(); <-done })
	return netip.MustParseAddrPort(address.String())
}

func TestResolverUDPRetryKeepsSocketAndSlowReply(t *testing.T) {
	var requests, dials atomic.Int32
	var mu sync.Mutex
	var ports []string
	third := make(chan struct{})
	server := resolverServer(t, "udp", func(w dns.ResponseWriter, request *dns.Msg) {
		count := requests.Add(1)
		mu.Lock()
		ports = append(ports, w.RemoteAddr().String())
		mu.Unlock()
		if count == 3 {
			close(third)
		}
		if count != 1 {
			return
		}
		// Reply to the first query only, after both retries have already been
		// sent. Discarding the original socket would lose this valid answer.
		select {
		case <-third:
		case <-time.After(2 * time.Second):
			return
		}
		_ = w.WriteMsg(new(dns.Msg).SetReply(request))
	})
	dial := func(ctx context.Context, network string, endpoint netip.AddrPort) (net.Conn, error) {
		dials.Add(1)
		if network != "udp4" || endpoint != server {
			t.Error("resolver/path changed")
		}
		return (&net.Dialer{}).DialContext(ctx, network, endpoint.String())
	}
	query := new(dns.Msg).SetQuestion("example.test.", dns.TypeA)
	answer, err := exchangeScoped(context.Background(), server, dial, "udp", query, 20*time.Millisecond)
	if err != nil || answer == nil || answer.Id != query.Id {
		t.Fatal(answer, err)
	}
	if dials.Load() != 1 || requests.Load() != 3 {
		t.Fatal("retry budget/socket ownership", dials.Load(), requests.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, port := range ports {
		if port != ports[0] {
			t.Fatal("retry changed socket", ports)
		}
	}
}

func TestResolverTCPAndIdentity(t *testing.T) {
	server := resolverServer(t, "tcp", func(w dns.ResponseWriter, q *dns.Msg) {
		stale := new(dns.Msg).SetReply(q)
		stale.Id++
		_ = w.WriteMsg(stale)
		wrong := new(dns.Msg).SetReply(q)
		wrong.Question = append([]dns.Question(nil), wrong.Question...)
		wrong.Question[0].Name = "wrong.test."
		_ = w.WriteMsg(wrong)
		_ = w.WriteMsg(new(dns.Msg).SetReply(q))
	})
	exchange, err := Resolver(server, func(ctx context.Context, network string, endpoint netip.AddrPort) (net.Conn, error) {
		if network != "tcp4" || endpoint != server {
			t.Error("resolver/transport changed")
		}
		return (&net.Dialer{}).DialContext(ctx, network, endpoint.String())
	})
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg).SetQuestion("example.test.", dns.TypeA)
	answer, err := exchange(context.Background(), "tcp", q)
	if err != nil || answer == nil || !matches(q, answer) {
		t.Fatal("valid reply lost after spurious answers", answer, err)
	}
}

func TestResolverFailsClosedForIPv6AndBindFailure(t *testing.T) {
	var dials atomic.Int32
	dial := func(context.Context, string, netip.AddrPort) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("private native bind detail")
	}
	v6, err := Resolver(netip.MustParseAddrPort("[2001:db8::53]:53"), dial)
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg).SetQuestion("example.test.", dns.TypeA)
	if _, err := v6(context.Background(), "udp", q); !errors.Is(err, ErrScopeUnavailable) || dials.Load() != 0 {
		t.Fatal("IPv6 DNS transport attempted", err, dials.Load())
	}
	v4, err := Resolver(netip.MustParseAddrPort("192.0.2.53:53"), dial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v4(context.Background(), "udp", q); !errors.Is(err, ErrScopeUnavailable) || dials.Load() != 1 {
		t.Fatal("binding failure fell back or leaked error", err, dials.Load())
	}
	if _, err := InterfaceDial("missing-native-interface", 2147483647); !errors.Is(err, ErrScopeUnavailable) {
		t.Fatal("missing scope accepted", err)
	}
}

func TestResolverCancellationJoinsNativeRead(t *testing.T) {
	entered := make(chan struct{}, 3)
	server := resolverServer(t, "udp", func(dns.ResponseWriter, *dns.Msg) { entered <- struct{}{} })
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := exchangeScoped(parent, server, func(ctx context.Context, network string, endpoint netip.AddrPort) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, endpoint.String())
		}, "udp", new(dns.Msg).SetQuestion("example.test.", dns.TypeA), time.Second)
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native exchange did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("native read did not stop")
	}
}
