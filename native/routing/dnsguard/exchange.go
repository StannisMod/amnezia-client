package dnsguard

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// NativeRequest is copied by an asynchronous host adapter before Dispatch
// returns. The host must use the connection's selected resolver/path.
type NativeRequest struct {
	ID      uint64
	Network string
	Wire    []byte
	Timeout time.Duration
}

type pendingExchange struct {
	cancel   context.CancelFunc
	ctx      context.Context
	id       uint16
	opcode   int
	query    []dns.Question
	complete bool
	result   chan *dns.Msg
}

// NativeExchange bridges native asynchronous DNS I/O without using a Go/default
// resolver. Dispatch and Cancel must return promptly and must not call Close
// inline; the native owner closes the bridge outside callback delivery.
type NativeExchange struct {
	mu       sync.Mutex
	next     uint64
	pending  map[uint64]*pendingExchange
	closed   bool
	active   sync.WaitGroup
	dispatch func(NativeRequest) error
	cancel   func(uint64)
}

func NewNativeExchange(dispatch func(NativeRequest) error, cancel func(uint64)) (*NativeExchange, error) {
	if dispatch == nil || cancel == nil {
		return nil, errors.New("native DNS requires explicit dispatch and cancellation")
	}
	return &NativeExchange{pending: make(map[uint64]*pendingExchange), dispatch: dispatch, cancel: cancel}, nil
}

func (b *NativeExchange) Exchange(parent context.Context, network string, request *dns.Msg) (*dns.Msg, error) {
	if parent == nil || request == nil || (network != "udp" && network != "tcp") {
		return nil, errors.New("invalid native DNS request")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	wire, err := request.Pack()
	if err != nil {
		return nil, errors.New("invalid native DNS message")
	}
	b.mu.Lock()
	if b.closed || len(b.pending) >= 256 {
		b.mu.Unlock()
		return nil, errors.New("native DNS exchange unavailable")
	}
	b.next++
	token := b.next
	entry := &pendingExchange{ctx: ctx, cancel: cancel, id: request.Id, opcode: request.Opcode,
		query: append([]dns.Question(nil), request.Question...), result: make(chan *dns.Msg, 1)}
	b.pending[token] = entry
	b.active.Add(1)
	b.mu.Unlock()
	defer b.active.Done()
	defer func() {
		b.mu.Lock()
		delete(b.pending, token)
		b.mu.Unlock()
	}()
	// Close/cancellation may race admission. Cancel is delivered after a
	// dispatched Start, never before it; late completions cannot reopen DNS.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	if err := b.dispatch(NativeRequest{ID: token, Network: network, Wire: wire, Timeout: timeout}); err != nil {
		b.cancel(token)
		return nil, errors.New("selected native DNS scope unavailable")
	}
	select {
	case <-ctx.Done():
		b.cancel(token)
		return nil, ctx.Err()
	case answer := <-entry.result:
		if err := ctx.Err(); err != nil {
			b.cancel(token)
			return nil, err
		}
		return answer, nil
	}
}

// Complete accepts exactly one correctly framed response for a live request.
// Wrong IDs, malformed packets, duplicates and post-cancellation callbacks are
// rejected. No host buffer is retained.
func (b *NativeExchange) Complete(token uint64, wire []byte) bool {
	if len(wire) < 12 || len(wire) > 65535 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	entry := b.pending[token]
	if b.closed || entry == nil || entry.complete || entry.ctx.Err() != nil {
		return false
	}
	answer := new(dns.Msg)
	if answer.Unpack(wire) != nil || !answer.Response || answer.Id != entry.id || answer.Opcode != entry.opcode {
		return false
	}
	if !(answer.Rcode != dns.RcodeSuccess && len(answer.Question) == 0) {
		if len(answer.Question) != len(entry.query) {
			return false
		}
		for i, question := range entry.query {
			reply := answer.Question[i]
			if !strings.EqualFold(reply.Name, question.Name) || reply.Qtype != question.Qtype || reply.Qclass != question.Qclass {
				return false
			}
		}
	}
	entry.complete = true
	select {
	case entry.result <- answer:
		return true
	default:
		return false
	}
}

func (b *NativeExchange) Close() error {
	b.mu.Lock()
	b.closed = true
	for _, entry := range b.pending {
		entry.cancel()
	}
	b.mu.Unlock()
	// All dispatch/cancel calls finish before the native host can be released.
	b.active.Wait()
	return nil
}
