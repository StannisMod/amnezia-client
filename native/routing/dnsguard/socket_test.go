package dnsguard

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func socketPair(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	return udp, tcp
}

func TestSocketFrontendWirePolicy(t *testing.T) {
	var forwarded atomic.Int32
	udp, tcp := socketPair(t)
	frontend, err := NewSocket(context.Background(), udp, tcp, func(ctx context.Context, network string, request *dns.Msg) (*dns.Msg, error) {
		forwarded.Add(1)
		if ctx.Err() != nil || network != "udp" && network != "tcp" {
			t.Error("scope/transport lost")
		}
		if request.Question[0].Qtype != dns.TypeA {
			t.Error("AAAA reached upstream")
		}
		if request.Question[0].Name == "unavailable.test." {
			return nil, errors.New("selected resolver unavailable")
		}
		reply := new(dns.Msg).SetReply(request)
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.9")}}
		return reply, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer frontend.Close()
	for _, network := range []string{"udp", "tcp"} {
		before := forwarded.Load()
		client := &dns.Client{Net: network, Timeout: time.Second}
		query := new(dns.Msg).SetQuestion("example.test.", dns.TypeAAAA)
		query.AuthenticatedData = true
		answer, _, err := client.Exchange(query, tcp.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if answer.Id != query.Id || answer.Rcode != dns.RcodeSuccess || answer.AuthenticatedData || len(answer.Answer) != 0 || len(answer.Ns) != 0 || forwarded.Load() != before {
			t.Fatal("invalid local NODATA", network, answer, forwarded.Load())
		}
		query.SetQuestion("example.test.", dns.TypeA)
		answer, _, err = client.Exchange(query, tcp.Addr().String())
		if err != nil || len(answer.Answer) != 1 || answer.Id != query.Id {
			t.Fatal("A not preserved", answer, err)
		}
		query.SetQuestion("unavailable.test.", dns.TypeA)
		answer, _, err = client.Exchange(query, tcp.Addr().String())
		if err != nil || answer.Rcode != dns.RcodeServerFailure {
			t.Fatal("resolver failure escaped", answer, err)
		}
	}
	if forwarded.Load() != 4 {
		t.Fatal("unexpected forwarding", forwarded.Load())
	}
}

func TestSocketFrontendRejectsMismatchedListeners(t *testing.T) {
	udp, _ := socketPair(t)
	_, other := socketPair(t)
	if f, err := NewSocket(context.Background(), udp, other, func(context.Context, string, *dns.Msg) (*dns.Msg, error) { panic("unpublished endpoint forwarded") }); err == nil {
		f.Close()
		t.Fatal("mismatched listener endpoints accepted")
	}
	if _, err := other.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("failed constructor retained TCP listener", err)
	}
	if _, err := udp.WriteTo([]byte{1}, udp.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("failed constructor retained UDP listener", err)
	}
}

func TestSocketFrontendCancellationJoinsExchange(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, exited := make(chan struct{}), make(chan struct{})
	udp, tcp := socketPair(t)
	f, err := NewSocket(parent, udp, tcp, func(ctx context.Context, _ string, _ *dns.Msg) (*dns.Msg, error) {
		close(entered)
		<-ctx.Done()
		close(exited)
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	replied := make(chan struct{})
	go func() {
		defer close(replied)
		_, _, _ = (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(new(dns.Msg).SetQuestion("example.test.", dns.TypeA), tcp.Addr().String())
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("exchange did not start")
	}
	cancel()
	stopped := make(chan struct{})
	go func() { _ = f.Close(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not join")
	}
	select {
	case <-exited:
	default:
		t.Fatal("released before scoped exchange exited")
	}
	<-replied
}

func TestSocketFrontendListenerExitInvalidatesEndpoint(t *testing.T) {
	udp, tcp := socketPair(t)
	f, err := NewSocket(context.Background(), udp, tcp, func(context.Context, string, *dns.Msg) (*dns.Msg, error) { return nil, errors.New("no forwarding") })
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_ = udp.Close()
	select {
	case <-f.Done():
	case <-time.After(time.Second):
		t.Fatal("native listener exit did not invalidate endpoint")
	}
	_ = f.Close()
	if _, err := tcp.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("surviving TCP listener not retired", err)
	}
}

func TestSocketFrontendRejectsWildcard(t *testing.T) {
	tcp, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if f, err := NewSocket(context.Background(), udp, tcp, func(context.Context, string, *dns.Msg) (*dns.Msg, error) { return nil, nil }); err == nil {
		f.Close()
		t.Fatal("wildcard DNS service accepted")
	}
}

type socketWriter struct {
	remote net.Addr
	writes int
}

func (w *socketWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *socketWriter) RemoteAddr() net.Addr        { return w.remote }
func (w *socketWriter) WriteMsg(*dns.Msg) error     { w.writes++; return nil }
func (w *socketWriter) Write(b []byte) (int, error) { w.writes++; return len(b), nil }
func (*socketWriter) Close() error                  { return nil }
func (*socketWriter) TsigStatus() error             { return nil }
func (*socketWriter) TsigTimersOnly(bool)           {}
func (*socketWriter) Hijack()                       {}

func TestSocketFrontendNeverServesRemoteVPNPeers(t *testing.T) {
	var forwarded int
	handler := newSocketHandler(context.Background(), func(_ context.Context, _ string, q *dns.Msg) (*dns.Msg, error) {
		forwarded++
		return new(dns.Msg).SetReply(q), nil
	})
	for _, remote := range []net.Addr{
		&net.UDPAddr{IP: net.ParseIP("198.51.100.254"), Port: 1234},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::254"), Port: 1234},
	} {
		w := &socketWriter{remote: remote}
		handler.ServeDNS(w, new(dns.Msg).SetQuestion("example.test.", dns.TypeA))
		handler.ServeDNS(w, new(dns.Msg).SetQuestion("example.test.", dns.TypeAAAA))
		if w.writes != 0 || forwarded != 0 {
			t.Fatal("remote peer used local DNS service", remote)
		}
	}
	w := &socketWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1234}}
	handler.ServeDNS(w, new(dns.Msg).SetQuestion("example.test.", dns.TypeA))
	if w.writes != 1 || forwarded != 1 {
		t.Fatal("local loopback alias was rejected")
	}
}
