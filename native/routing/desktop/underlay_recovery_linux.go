//go:build linux && !android

package desktop

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/tunnel"
)

// A single actor owns established-path recovery. No failure budget here may
// release the TUN, FakeIP, peer or TCP stacks. Initial connection remains owned
// by the bounded client state machine; explicit stop cancels this actor first.
type underlayRecovery struct {
	cancel                       context.CancelFunc
	done                         chan struct{}
	hints                        chan struct{}
	mu                           sync.Mutex
	endpoint                     netip.AddrPort
	pathChanges, probes, reopens atomic.Uint64
}

type recoveryPolicy struct {
	route                                                string
	observed, available, established, pending, needProbe bool
	rx, tx, handshake                                    uint64
	stalled, lastProbe, next                             time.Time
	delay, stale                                         time.Duration
	invalidate                                           func()
	probe                                                func() error
	refresh                                              func() error
}

func (p *recoveryPolicy) step(now time.Time, route string, available bool, stats tunnel.Stats, hint bool) {
	changed := p.observed && (p.route != route || p.available != available)
	p.observed = true
	p.route = route
	p.available = available
	handshakeProgress := stats.LastHandshake != p.handshake
	progress := stats.RXBytes != p.rx || handshakeProgress
	outgoing := stats.TXBytes != p.tx
	p.rx, p.tx, p.handshake = stats.RXBytes, stats.TXBytes, stats.LastHandshake
	if stats.LastHandshake > 0 {
		p.established = true
	}
	if !p.established {
		return
	}
	if progress {
		p.stalled = time.Time{}
	}
	// Queued packets from the retired local route can arrive after a switch.
	// A fresh authenticated handshake verifies the newly probed path.
	if handshakeProgress && p.pending {
		p.pending = false
		p.needProbe = false
		p.delay = 0
	}
	if outgoing && p.stalled.IsZero() {
		p.stalled = now
	}
	if changed {
		p.invalidate()
		p.pending = false
		p.needProbe = true
		p.delay = 0
	}
	if !available {
		return
	}
	stale := p.stale
	if stale <= 0 {
		stale = 240 * time.Second
	}
	if (hint || (!p.stalled.IsZero() && now.Sub(p.stalled) >= stale)) && !p.pending {
		p.needProbe = true
	}
	if p.needProbe {
		if !p.pending && (p.lastProbe.IsZero() || now.Sub(p.lastProbe) >= 5*time.Second) {
			p.probe()
			p.lastProbe = now
			p.pending = true
			p.needProbe = false
			p.delay = 5 * time.Second
			p.next = now.Add(p.delay)
		}
	}
	if p.pending && !now.Before(p.next) {
		// Submission/open success is not proof of reachability. Only later
		// authenticated RX/handshake progress ends the recovery attempt.
		p.refresh()
		p.delay *= 2
		if p.delay > 30*time.Second {
			p.delay = 30 * time.Second
		}
		p.next = now.Add(p.delay)
	}
}
func startUnderlayRecovery(ctx context.Context, endpoint netip.AddrPort, stale time.Duration, stats func() (tunnel.Stats, error), invalidate func(), probe, refresh func() error) *underlayRecovery {
	ctx, cancel := context.WithCancel(ctx)
	r := &underlayRecovery{cancel: cancel, done: make(chan struct{}), hints: make(chan struct{}, 1), endpoint: endpoint}
	initial, routeErr := protectedRouteFingerprint(endpoint)
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		policy := recoveryPolicy{route: initial, observed: true, available: routeErr == nil, stale: stale,
			invalidate: func() { r.pathChanges.Add(1); invalidate() },
			probe:      func() error { r.probes.Add(1); return probe() },
			refresh:    func() error { r.reopens.Add(1); return refresh() }}
		for {
			hint := false
			select {
			case <-ctx.Done():
				return
			case <-r.hints:
				hint = true
			case <-ticker.C:
			}
			r.mu.Lock()
			remote := r.endpoint
			r.mu.Unlock()
			route, err := protectedRouteFingerprint(remote)
			state, statsErr := stats()
			if statsErr != nil {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			policy.step(time.Now(), route, err == nil, state, hint)
		}
	}()
	return r
}
func (r *underlayRecovery) hint(endpoint netip.AddrPort) {
	if endpoint.IsValid() {
		r.mu.Lock()
		r.endpoint = endpoint
		r.mu.Unlock()
	}
	select {
	case r.hints <- struct{}{}:
	default:
	}
}
func (r *underlayRecovery) close() { r.cancel(); <-r.done }
func (r *underlayRecovery) diagnostics() map[string]uint64 {
	return map[string]uint64{"path_changes": r.pathChanges.Load(), "probes": r.probes.Load(), "reopens": r.reopens.Load()}
}
