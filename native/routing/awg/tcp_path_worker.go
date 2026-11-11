package awg

import (
	"context"
	"net/netip"
	"time"
)

type tcpPathWorker struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// Probe only after a real TCP timeout and while an owned socket still needs
// recovery. The endpoint hint stops measurements after ACK recovery, including
// when the normal RTO has already backed off beyond the polling interval.
func startTCPPathWorker(parent context.Context, flow *FlowStack, peer netip.Addr) *tcpPathWorker {
	ctx, cancel := context.WithCancel(parent)
	worker := &tcpPathWorker{cancel: cancel, done: make(chan struct{})}
	lastTimeouts := flow.stack.Stats().TCP.Timeouts.Value()
	go func() {
		defer close(worker.done)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		pending := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-flow.done:
				return
			case <-ticker.C:
			case <-flow.tcpPathWake:
				pending = true
			}
			timeouts := flow.stack.Stats().TCP.Timeouts.Value()
			if timeouts != lastTimeouts {
				pending = true
				lastTimeouts = timeouts
			}
			if !pending {
				continue
			}
			if !flow.hasRecoveringTCP() {
				pending = false
				continue
			}
			probeCtx, stop := context.WithTimeout(ctx, 400*time.Millisecond)
			proof, err := flow.verifyTCPPath(probeCtx, peer)
			stop()
			if err == nil && ctx.Err() == nil {
				flow.dispatchTCPPathProof(proof)
			}
		}
	}()
	return worker
}

func (w *tcpPathWorker) stop() {
	if w != nil {
		w.cancel()
		<-w.done
	}
}

func (s *FlowStack) hasRecoveringTCP() bool {
	if !s.begin() {
		return false
	}
	defer s.active.Done()
	for _, conn := range s.tcpConnectionsSnapshot() {
		hint, ok := any(conn).(interface{ NeedsVerifiedPathProbe() bool })
		if ok && hint.NeedsVerifiedPathProbe() {
			return true
		}
	}
	return false
}
