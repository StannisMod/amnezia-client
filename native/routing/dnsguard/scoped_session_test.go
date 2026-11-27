package dnsguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type scopedResponseWriter struct{ response func(*dns.Msg) }

func (scopedResponseWriter) LocalAddr() net.Addr  { return &net.UDPAddr{Port: 53} }
func (scopedResponseWriter) RemoteAddr() net.Addr { return &net.UDPAddr{Port: 40000} }
func (w scopedResponseWriter) WriteMsg(message *dns.Msg) error {
	if w.response != nil {
		w.response(message)
	}
	return nil
}
func (scopedResponseWriter) Write(wire []byte) (int, error) { return len(wire), nil }
func (scopedResponseWriter) Close() error                   { return nil }
func (scopedResponseWriter) TsigStatus() error              { return nil }
func (scopedResponseWriter) TsigTimersOnly(bool)            {}
func (scopedResponseWriter) Hijack()                        {}

func TestScopedPacketSessionRejectsImplicitOrMixedExchangeOwnership(t *testing.T) {
	var releases atomic.Int32
	callbacks := packetCallbacks(&releases)
	address := netip.MustParseAddr("198.19.255.1")
	if s, err := NewScopedPacketSession(context.Background(), address, nil, callbacks); err == nil || s != nil {
		t.Fatal("accepted missing scoped exchange")
	}
	exchange := func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("unadmitted scope ran")
		return nil, nil
	}
	if s, err := NewScopedPacketSession(context.Background(), address, exchange, callbacks); err == nil || s != nil {
		t.Fatal("accepted host fallback alongside explicit scope")
	}
	if releases.Load() != 2 {
		t.Fatalf("host releases=%d", releases.Load())
	}
}

func TestScopedPacketSessionCloseJoinsUninterruptibleNetworkBind(t *testing.T) {
	var releases, failures atomic.Int32
	callbacks := packetCallbacks(&releases)
	callbacks.Dispatch, callbacks.Cancel = nil, nil
	callbacks.Failed = func() { failures.Add(1) }
	started, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s, err := NewScopedPacketSession(context.Background(), netip.MustParseAddr("198.19.255.1"),
		func(ctx context.Context, _ string, _ *dns.Msg) (*dns.Msg, error) {
			close(started)
			<-unblock // Simulate a public Network.bindSocket IPC already in flight.
			return nil, ctx.Err()
		}, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { once.Do(func() { close(unblock) }); s.Close() })
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		s.frontend.udp.Handler.ServeDNS(scopedResponseWriter{}, new(dns.Msg).SetQuestion("bind.example.", dns.TypeA))
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scoped bind not admitted")
	}
	s.Quiesce()
	if s.Resume() {
		t.Fatal("resumed while a prior native bind remains in flight")
	}
	joined := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() { s.Close(); joined <- struct{}{} }()
	}
	select {
	case <-joined:
		t.Fatal("host retired before native bind joined")
	case <-time.After(30 * time.Millisecond):
	}
	if releases.Load() != 0 {
		t.Fatal("retained host released during native bind")
	}
	once.Do(func() { close(unblock) })
	for i := 0; i < 2; i++ {
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Fatal("scoped close failed to join")
		}
	}
	<-handlerDone
	if releases.Load() != 1 || failures.Load() != 0 {
		t.Fatalf("release=%d failures=%d", releases.Load(), failures.Load())
	}
	if s.Complete(1, make([]byte, 12)) || s.Reject(1) {
		t.Fatal("scoped session accepted host-I/O fallback response")
	}
}

func TestScopedPacketSessionQuiesceKeepsLocalNODATAAndResumesOnlyJoinedScope(t *testing.T) {
	var releases, forwards atomic.Int32
	callbacks := packetCallbacks(&releases)
	callbacks.Dispatch, callbacks.Cancel = nil, nil
	s, err := NewScopedPacketSession(context.Background(), netip.MustParseAddr("198.19.255.1"),
		func(_ context.Context, _ string, request *dns.Msg) (*dns.Msg, error) {
			forwards.Add(1)
			return new(dns.Msg).SetReply(request), nil
		}, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	request := func(kind uint16) *dns.Msg {
		var answer *dns.Msg
		s.frontend.udp.Handler.ServeDNS(scopedResponseWriter{response: func(message *dns.Msg) { answer = message }},
			new(dns.Msg).SetQuestion("quiesced.example.", kind))
		if answer == nil {
			t.Fatal("local DNS handler did not respond")
		}
		return answer
	}
	s.Quiesce()
	if a := request(dns.TypeAAAA); a.Rcode != dns.RcodeSuccess || len(a.Answer) != 0 || a.AuthenticatedData {
		t.Fatal("quiesce disabled local unauthenticated NODATA")
	}
	if request(dns.TypeA).Rcode != dns.RcodeServerFailure || forwards.Load() != 0 {
		t.Fatal("quiesced scope forwarded or selected a fallback")
	}
	if !s.Resume() {
		t.Fatal("joined scope could not resume")
	}
	if request(dns.TypeA).Rcode != dns.RcodeSuccess || forwards.Load() != 1 {
		t.Fatal("resumed selected scope did not forward")
	}
	s.Close()
	if s.Resume() || releases.Load() != 1 {
		t.Fatal("retired scope resumed or leaked host")
	}
}
