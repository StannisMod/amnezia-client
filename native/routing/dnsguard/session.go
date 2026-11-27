package dnsguard

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

// PacketCallbacks belong to the native adapter's retained host. All calls must
// return without synchronously closing their own session: enqueue cleanup on
// the generation's owner instead. Release runs only after all callbacks join.
type PacketCallbacks struct {
	Write    func([]byte) bool
	Dispatch func(NativeRequest) error
	Cancel   func(uint64)
	Failed   func()
	Release  func()
}

// PacketSession is a DNS-only in-memory frontend with a joined native host.
// It owns no OS reader, interface, resolver selection or application data path.
type PacketSession struct {
	mu            sync.RWMutex
	closed        bool
	failed        atomic.Bool
	callback      PacketCallbacks
	cancel        context.CancelFunc
	frontend      *Frontend
	exchange      *NativeExchange
	done          chan struct{}
	once          sync.Once
	forward       sync.WaitGroup
	ctx           context.Context
	scopeMu       sync.Mutex
	scopeCtx      context.Context
	scopeCancel   context.CancelFunc
	quiesced      bool
	forwardClosed bool
	forwarding    int
	tunnel        *tunnelPacketScope
}

// NewPacketSession takes ownership of callbacks.Release even on error, if it
// is nonnil. The adapter must prepare before publication and retain the session
// until its native reader and callbacks have joined.
func NewPacketSession(parent context.Context, address netip.Addr, callbacks PacketCallbacks) (*PacketSession, error) {
	return newPacketSession(parent, address, callbacks, nil)
}

// NewScopedPacketSession forwards through an explicit, cancellable exchange in
// this existing runtime. It never invents a resolver or native network binding.
// Dispatch/Cancel callbacks must be nil: no implicit host-I/O fallback exists.
func NewScopedPacketSession(parent context.Context, address netip.Addr, exchange Exchange,
	callbacks PacketCallbacks) (*PacketSession, error) {
	if exchange == nil {
		if callbacks.Release != nil {
			callbacks.Release()
		}
		return nil, errors.New("native DNS requires an explicit scoped exchange")
	}
	return newPacketSession(parent, address, callbacks, exchange)
}

func newPacketSession(parent context.Context, address netip.Addr, callbacks PacketCallbacks,
	scoped Exchange) (*PacketSession, error) {
	return newPacketSessionScoped(parent, address, callbacks, scoped, nil)
}

func newPacketSessionScoped(parent context.Context, address netip.Addr, callbacks PacketCallbacks,
	scoped Exchange, tunnel *tunnelPacketScope) (*PacketSession, error) {
	owned := true
	defer func() {
		if owned && callbacks.Release != nil {
			callbacks.Release()
		}
	}()
	if parent == nil || parent.Err() != nil || callbacks.Write == nil ||
		callbacks.Failed == nil || callbacks.Release == nil {
		return nil, errors.New("native DNS host callbacks are incomplete")
	}
	if (scoped == nil && (callbacks.Dispatch == nil || callbacks.Cancel == nil)) ||
		(scoped != nil && (callbacks.Dispatch != nil || callbacks.Cancel != nil)) {
		return nil, errors.New("native DNS exchange ownership is ambiguous")
	}
	ctx, cancel := context.WithCancel(parent)
	scopeCtx, scopeCancel := context.WithCancel(ctx)
	s := &PacketSession{callback: callbacks, ctx: ctx, cancel: cancel, done: make(chan struct{}),
		scopeCtx: scopeCtx, scopeCancel: scopeCancel, tunnel: tunnel}
	if tunnel != nil {
		tunnel.failed = s.reportFailure
	}
	var err error
	if scoped == nil {
		s.exchange, err = NewNativeExchange(func(request NativeRequest) error {
			s.mu.RLock()
			defer s.mu.RUnlock()
			if s.closed || ctx.Err() != nil {
				return context.Canceled
			}
			return callbacks.Dispatch(request)
		}, callbacks.Cancel)
		if err != nil {
			cancel()
			return nil, err
		}
		scoped = s.exchange.Exchange
	}
	s.frontend, err = newFrontend(ctx, address, func(ctx context.Context, network string, request *dns.Msg) (*dns.Msg, error) {
		s.scopeMu.Lock()
		if s.forwardClosed || s.quiesced {
			s.scopeMu.Unlock()
			return nil, context.Canceled
		}
		s.forwarding++
		s.forward.Add(1)
		scope := s.scopeCtx
		s.scopeMu.Unlock()
		defer func() {
			s.scopeMu.Lock()
			s.forwarding--
			s.scopeMu.Unlock()
			s.forward.Done()
		}()
		requestCtx, stop := context.WithCancel(ctx)
		cancelScope := context.AfterFunc(scope, stop)
		defer stop()
		defer cancelScope()
		if requestCtx.Err() != nil {
			return nil, requestCtx.Err()
		}
		return scoped(requestCtx, network, request)
	}, tunnel)
	if err != nil {
		cancel()
		if s.exchange != nil {
			s.exchange.Close()
		}
		return nil, err
	}
	owned = false
	go s.writeReplies()
	return s, nil
}

func (s *PacketSession) reportFailure() {
	if !s.failed.CompareAndSwap(false, true) {
		return
	}
	s.cancel()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.closed {
		s.callback.Failed()
	}
}

func (s *PacketSession) writeReplies() {
	defer close(s.done)
	data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
	for {
		count, err := s.frontend.Device().Read(data, sizes, 0)
		if err != nil {
			s.reportFailure()
			return
		}
		if count > 0 {
			s.mu.RLock()
			if s.closed {
				s.mu.RUnlock()
				return
			}
			// Bytes are borrowed only for this callback. The native adapter
			// must copy when enqueueing onto its existing I/O thread.
			ok := s.callback.Write(data[0][:sizes[0]])
			s.mu.RUnlock()
			if !ok {
				s.reportFailure()
				return
			}
		}
	}
}

// Feed returns 0 for untouched native traffic, 1 for consumed DNS-owned input,
// and -1 for a failed/retiring frontend. Unowned packets are never copied.
func (s *PacketSession) Feed(packet []byte) int {
	s.mu.RLock()
	if s.closed || s.failed.Load() {
		s.mu.RUnlock()
		return -1
	}
	if !s.frontend.HandlesPacket(packet) {
		s.mu.RUnlock()
		return 0
	}
	copyOfPacket := append([]byte(nil), packet...)
	_, err := s.frontend.Device().Write([][]byte{copyOfPacket}, 0)
	s.mu.RUnlock()
	if err != nil {
		s.reportFailure()
		return -1
	}
	return 1
}

func (s *PacketSession) Complete(token uint64, wire []byte) bool {
	return s.exchange != nil && s.exchange.Complete(token, wire)
}

func (s *PacketSession) Reject(token uint64) bool {
	return s.exchange != nil && s.exchange.Reject(token)
}

// Quiesce cancels all selected-scope I/O without waiting on one blocked host
// callback and without disabling local AAAA NODATA. Quiesce EVERY scope before
// joining any one of them.
func (s *PacketSession) Quiesce() {
	s.scopeMu.Lock()
	s.quiesced = true
	cancel := s.scopeCancel
	s.scopeMu.Unlock()
	cancel()
}

// Resume never overlaps a previous scope's still-pending native socket/bind.
func (s *PacketSession) Resume() bool {
	s.scopeMu.Lock()
	defer s.scopeMu.Unlock()
	if s.forwardClosed || s.ctx.Err() != nil {
		return false
	}
	if !s.quiesced {
		return true
	}
	if s.forwarding != 0 || (s.tunnel != nil && !s.tunnel.idle()) {
		return false
	}
	s.scopeCtx, s.scopeCancel = context.WithCancel(s.ctx)
	s.quiesced = false
	return true
}

func (s *PacketSession) Close() {
	s.once.Do(func() {
		s.scopeMu.Lock()
		s.forwardClosed = true
		s.scopeMu.Unlock()
		s.Quiesce()
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.cancel()
		s.frontend.Close()
		if s.exchange != nil {
			s.exchange.Close()
		}
		s.forward.Wait()
		<-s.done
		s.callback.Release()
	})
}
