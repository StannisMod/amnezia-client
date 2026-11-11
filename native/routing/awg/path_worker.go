package awg

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

type pathMTUWorker struct {
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	checkCancel context.CancelFunc
	wake        chan struct{}
	done        chan struct{}
	generation  uint64
}

func startPathMTUWorker(parent context.Context, flow *FlowStack, peer netip.Addr) *pathMTUWorker {
	ctx, cancel := context.WithCancel(parent)
	w := &pathMTUWorker{ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{})}
	controller, _ := NewPathMTUController(flow, peer) // validated before transport start
	controller.apply = func(ctx context.Context, mtu int) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		return flow.SetPathMTU(mtu)
	}
	go func() {
		defer close(w.done)
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		// A mature path can deteriorate just after the periodic probe. TCP
		// timeout growth is a reason to measure sooner, never MTU evidence by
		// itself. The controller still requires live small probes and repeated
		// size-dependent failures before changing the private link.
		lossPoll := time.NewTicker(time.Second)
		defer lossPoll.Stop()
		lastTimeouts := flow.stack.Stats().TCP.Timeouts.Value()
		var lastLossCheck time.Time
		pendingLoss := false
		var generation uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			case <-w.wake:
			case now := <-lossPoll.C:
				timeouts := flow.stack.Stats().TCP.Timeouts.Value()
				if timeouts != lastTimeouts {
					pendingLoss = true
					lastTimeouts = timeouts
				}
				if !pendingLoss || (!lastLossCheck.IsZero() && now.Sub(lastLossCheck) < 5*time.Second) {
					continue
				}
				pendingLoss = false
				lastLossCheck = now
			}
			w.mu.Lock()
			checkCtx, stop := context.WithTimeout(ctx, 12*time.Second)
			w.checkCancel = stop
			reset := generation != w.generation
			generation = w.generation
			w.mu.Unlock()
			if reset {
				controller.mu.Lock()
				controller.raiseCandidate = 0
				controller.raiseCount = 0
				controller.mu.Unlock()
			}
			controller.Check(checkCtx)
			stop()
			w.mu.Lock()
			w.checkCancel = nil
			w.mu.Unlock()
			timer.Reset(30 * time.Second)
		}
	}()
	return w
}

func (w *pathMTUWorker) invalidate() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.generation++
	if w.checkCancel != nil {
		w.checkCancel()
	}
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}
func (w *pathMTUWorker) stop() {
	if w != nil {
		w.cancel()
		<-w.done
	}
}
