package dnsguard

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNativeExchangeValidatesResponsesAndCopiesHostBuffers(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			var bridge *NativeExchange
			var err error
			bridge, err = NewNativeExchange(func(request NativeRequest) error {
				if request.Network != network || request.Timeout <= 0 || request.Timeout > 5*time.Second {
					t.Fatal("native dispatch lost protocol/deadline")
				}
				query := new(dns.Msg)
				if err := query.Unpack(request.Wire); err != nil {
					return err
				}
				answer := new(dns.Msg).SetReply(query)
				wrongID := answer.Copy()
				wrongID.Id++
				wrongWire, _ := wrongID.Pack()
				if bridge.Complete(request.ID, wrongWire) {
					t.Fatal("wrong DNS transaction accepted")
				}
				wrongQuery := answer.Copy()
				wrongQuery.Question[0].Name = "different.example."
				wrongWire, _ = wrongQuery.Pack()
				if bridge.Complete(request.ID, wrongWire) {
					t.Fatal("different DNS question accepted")
				}
				if bridge.Complete(request.ID, []byte{1, 2, 3}) {
					t.Fatal("malformed native response accepted")
				}
				wire, _ := answer.Pack()
				if !bridge.Complete(request.ID, wire) || bridge.Complete(request.ID, wire) {
					t.Fatal("completion did not have exactly-once semantics")
				}
				for i := range wire {
					wire[i] = 0
				}
				return nil
			}, func(uint64) { t.Error("completed exchange was unnecessarily cancelled") })
			if err != nil {
				t.Fatal(err)
			}
			defer bridge.Close()
			request := new(dns.Msg).SetQuestion("managed.example.", dns.TypeA)
			answer, err := bridge.Exchange(context.Background(), network, request)
			if err != nil || answer == nil || answer.Id != request.Id || answer.Question[0].Name != request.Question[0].Name {
				t.Fatalf("valid native response lost/corrupted: %v", err)
			}
		})
	}
}

func TestNativeExchangeCloseCancelsRequestsAndRejectsLateCallbacks(t *testing.T) {
	started := make(chan NativeRequest, 1)
	cancelled := make(chan uint64, 1)
	bridge, err := NewNativeExchange(func(r NativeRequest) error { started <- r; return nil },
		func(id uint64) { cancelled <- id })
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	request := new(dns.Msg).SetQuestion("managed.example.", dns.TypeA)
	go func() { _, err := bridge.Exchange(context.Background(), "udp", request); result <- err }()
	entry := <-started
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("close did not cancel pending exchange: %v", err)
	}
	if id := <-cancelled; id != entry.ID {
		t.Fatal("native cancellation targeted a different request")
	}
	wire, _ := new(dns.Msg).SetReply(request).Pack()
	if bridge.Complete(entry.ID, wire) {
		t.Fatal("late callback was accepted after native host release")
	}
	if _, err := bridge.Exchange(context.Background(), "udp", request); err == nil {
		t.Fatal("closed exchange bridge admitted another request")
	}
}

func TestNativeExchangeCancellationCannotPrecedeInFlightDispatch(t *testing.T) {
	started, release := make(chan NativeRequest, 1), make(chan struct{})
	cancelled := make(chan uint64, 1)
	bridge, err := NewNativeExchange(func(r NativeRequest) error { started <- r; <-release; return nil },
		func(id uint64) { cancelled <- id })
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := bridge.Exchange(context.Background(), "tcp", new(dns.Msg).SetQuestion("managed.example.", dns.TypeA))
		result <- err
	}()
	entry := <-started
	bridge.mu.Lock()
	requestContext := bridge.pending[entry.ID].ctx
	bridge.mu.Unlock()
	closed := make(chan struct{})
	go func() { _ = bridge.Close(); close(closed) }()
	<-requestContext.Done()
	select {
	case <-cancelled:
		t.Fatal("Cancel ran before native Dispatch returned")
	default:
	}
	close(release)
	<-closed
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("in-flight dispatch survived close: %v", err)
	}
	if id := <-cancelled; id != entry.ID {
		t.Fatal("missing cancellation after in-flight Dispatch")
	}
}

func TestNativeExchangeDoesNotExposeScopeErrorContentsOrFallback(t *testing.T) {
	dispatches, cancellations := 0, 0
	bridge, err := NewNativeExchange(func(NativeRequest) error {
		dispatches++
		return errors.New("private-resolver-and-credential-data")
	}, func(uint64) { cancellations++ })
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	_, err = bridge.Exchange(context.Background(), "udp", new(dns.Msg).SetQuestion("managed.example.", dns.TypeA))
	if err == nil || strings.Contains(err.Error(), "private") || dispatches != 1 || cancellations != 1 {
		t.Fatal("native DNS error leaked data or retried a different scope")
	}
}
