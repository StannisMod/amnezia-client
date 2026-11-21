package engine

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

type udpDNSRegressionDialer struct{ net.Dialer }

type udpDNSStub struct {
	adapter.DNSTransport
	exchange func(context.Context, *dns.Msg) (*dns.Msg, error)
}

func (s *udpDNSStub) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	return s.exchange(ctx, message)
}

func TestUDPDNSRetryDoesNotRepeatNegativeRepliesOrNonQueryOperations(t *testing.T) {
	for _, opcode := range []int{dns.OpcodeQuery, dns.OpcodeUpdate} {
		var calls atomic.Int32
		delegate := &udpDNSStub{exchange: func(_ context.Context, query *dns.Msg) (*dns.Msg, error) {
			calls.Add(1)
			answer := new(dns.Msg)
			answer.SetRcode(query, dns.RcodeNameError)
			return answer, nil
		}}
		wrapped := &retryingUDPDNS{DNSTransport: delegate}
		query := new(dns.Msg)
		query.SetQuestion("negative.test.", dns.TypeA)
		query.Opcode = opcode
		answer, err := wrapped.Exchange(context.Background(), query)
		if err != nil || answer.Rcode != dns.RcodeNameError || calls.Load() != 1 {
			t.Fatalf("authoritative result/non-query operation was retried: opcode=%d calls=%d err=%v", opcode, calls.Load(), err)
		}
	}
}

func (d udpDNSRegressionDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, destination.String())
}

func (d udpDNSRegressionDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func TestUDPDNSPinnedTransportLostDatagramRedControlAndRecovery(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var received atomic.Int32
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, address, err := server.ReadFrom(buffer)
			if err != nil {
				return
			}
			if received.Add(1) == 1 {
				continue // Drop exactly the first request, not a returned error.
			}
			query := new(dns.Msg)
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			response := new(dns.Msg)
			response.SetReply(query)
			packet, err := response.Pack()
			if err == nil {
				server.WriteTo(packet, address)
			}
		}
	}()
	delegate := transport.NewUDPRaw(log.NewNOPFactory().NewLogger("test"),
		boxDNS.NewTransportAdapter("udp", "test", nil), udpDNSRegressionDialer{},
		M.ParseSocksaddr(server.LocalAddr().String()))
	defer delegate.Reset()
	query := new(dns.Msg)
	query.SetQuestion("loss.test.", dns.TypeA)
	baseline, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err = delegate.Exchange(baseline, query)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) || received.Load() != 1 {
		t.Fatalf("red control did not reproduce no-retransmission stall: %v packets=%d", err, received.Load())
	}
	delegate.Reset()
	received.Store(0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	retrying := &retryingUDPDNS{DNSTransport: delegate}
	answer, err := retrying.Exchange(ctx, query)
	if err != nil || answer == nil || answer.Id != query.Id || received.Load() < 2 {
		t.Fatalf("same UDP transport did not recover the lost datagram: %v packets=%d", err, received.Load())
	}
}

func TestUDPDNSLostFirstResponseRecoversWithoutWaitingForOuterDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	query := new(dns.Msg)
	query.SetQuestion("loss.test.", dns.TypeA)
	query.Id = 123
	var calls atomic.Int32
	cancelled := make(chan struct{})
	answer, err := exchangeUDPWithRetry(ctx, query, 10*time.Millisecond,
		func(attempt context.Context, copy *dns.Msg) (*dns.Msg, error) {
			if copy == query || copy.Question[0] != query.Question[0] {
				t.Error("attempt did not preserve an independent query")
			}
			if calls.Add(1) == 1 {
				// The datagram or its reply is lost, not a reported I/O error.
				<-attempt.Done()
				close(cancelled)
				return nil, attempt.Err()
			}
			response := new(dns.Msg)
			response.SetReply(copy)
			return response, nil
		})
	if err != nil || answer == nil || answer.Id != 123 || calls.Load() < 2 || calls.Load() > 3 {
		t.Fatalf("lost response not recovered: answer=%v err=%v attempts=%d", answer, err, calls.Load())
	}
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("losing attempt was not cancelled")
	}
}

func TestUDPDNSRetryStillAcceptsSlowOriginalAndPreservesNegativeReply(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second := make(chan struct{})
	var calls atomic.Int32
	query := new(dns.Msg)
	query.SetQuestion("negative.test.", dns.TypeAAAA)
	answer, err := exchangeUDPWithRetry(ctx, query, 10*time.Millisecond,
		func(attempt context.Context, copy *dns.Msg) (*dns.Msg, error) {
			n := calls.Add(1)
			if n == 1 {
				<-second
				response := new(dns.Msg)
				response.SetRcode(copy, dns.RcodeNameError)
				return response, nil
			}
			if n == 2 {
				close(second)
			}
			<-attempt.Done()
			return nil, attempt.Err()
		})
	if err != nil || answer == nil || answer.Rcode != dns.RcodeNameError {
		t.Fatalf("slow authoritative negative reply was discarded: %v %v", answer, err)
	}
}

func TestUDPDNSRetryBoundsAttemptsAndHonorsCancellation(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("unavailable.test.", dns.TypeA)
	var calls atomic.Int32
	failure := errors.New("controlled transport failure")
	_, err := exchangeUDPWithRetry(context.Background(), query, time.Millisecond,
		func(context.Context, *dns.Msg) (*dns.Msg, error) {
			calls.Add(1)
			return nil, failure
		})
	if !errors.Is(err, failure) || calls.Load() != 3 {
		t.Fatalf("retry budget not enforced: %v attempts=%d", err, calls.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = exchangeUDPWithRetry(ctx, query, time.Millisecond,
		func(context.Context, *dns.Msg) (*dns.Msg, error) {
			t.Error("cancelled query was sent")
			return nil, nil
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation lost", err)
	}
}
