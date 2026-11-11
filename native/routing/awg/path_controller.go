package awg

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

type PathMTUResult struct {
	State                 string
	Before, After, Probes int
}

// PathMTUController owns one peer's private flow MTU. Callers serialize its
// lifetime with the transport and cancel measurements on endpoint changes.
// A failed liveness probe is inconclusive, never evidence for lowering MTU.
type PathMTUController struct {
	mu                         sync.Mutex
	flow                       *FlowStack
	peer                       netip.Addr
	timeout                    time.Duration
	raiseCandidate, raiseCount int
	apply                      func(context.Context, int) error
}

func NewPathMTUController(flow *FlowStack, peer netip.Addr) (*PathMTUController, error) {
	peer = peer.Unmap()
	if flow == nil || !peer.IsValid() || peer.Zone() != "" || !peer.IsGlobalUnicast() {
		return nil, errors.New("invalid MTU peer")
	}
	return &PathMTUController{flow: flow, peer: peer, timeout: 250 * time.Millisecond}, nil
}

// Check performs a bounded measurement. Three successes out of separate
// checks are required for an increase; a verified decrease applies now.
func (c *PathMTUController) Check(ctx context.Context) (PathMTUResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	before, _ := c.flow.MTU()
	result := PathMTUResult{State: "inconclusive", Before: before, After: before}
	if _, ok := ctx.Deadline(); !ok {
		return result, errors.New("MTU check requires a deadline")
	}
	passes := func(size int) bool {
		success := 0
		for i := 0; i < 3; i++ {
			if ctx.Err() != nil {
				return false
			}
			probeCtx, cancel := context.WithTimeout(ctx, c.timeout)
			err := c.flow.ProbePath(probeCtx, c.peer, size)
			cancel()
			result.Probes++
			if err == nil {
				success++
			}
		}
		return success >= 2
	}
	reset := func() { c.raiseCandidate = 0; c.raiseCount = 0 }
	inconclusive := func() (PathMTUResult, error) { reset(); return result, ctx.Err() }
	if !passes(128) {
		return inconclusive()
	}
	candidate := c.flow.maximumMTU
	if !passes(candidate) {
		minimum := c.flow.minimumMTU
		if !passes(minimum) || !passes(128) {
			return inconclusive()
		}
		low, high := minimum, candidate
		for high-low > 16 {
			mid := (low + (high-low)/2) / 16 * 16
			if mid <= low {
				mid = low + 1
			}
			if passes(mid) {
				low = mid
			} else if passes(128) {
				high = mid
			} else {
				return inconclusive()
			}
		}
		candidate = low - 16
		if candidate < minimum {
			candidate = minimum
		}
		if !passes(candidate) || passes(high) || !passes(128) {
			return inconclusive()
		}
	}
	if err := ctx.Err(); err != nil {
		reset()
		return result, err
	}
	if candidate == before {
		reset()
		result.State = "unchanged"
		return result, nil
	}
	if candidate > before {
		if c.raiseCandidate != candidate {
			c.raiseCandidate = candidate
			c.raiseCount = 0
		}
		c.raiseCount++
		if c.raiseCount < 3 {
			result.State = "increase_pending"
			return result, nil
		}
	}
	apply := c.apply
	if apply == nil {
		apply = func(_ context.Context, mtu int) error { return c.flow.SetPathMTU(mtu) }
	}
	if err := apply(ctx, candidate); err != nil {
		reset()
		return result, err
	}
	reset()
	result.After = candidate
	result.State = "reduced"
	if candidate > before {
		result.State = "increased"
	}
	return result, nil
}
