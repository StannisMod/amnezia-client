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
	cancel                                        context.CancelFunc
	done                                          chan struct{}
	hints                                         chan struct{}
	mu                                            sync.Mutex
	endpoint                                      netip.AddrPort
	pathChanges, probes, reopens, endpointChanges atomic.Uint64
	revision                                      uint64
}

type recoveryPolicy struct {
	route                                                string
	observed, available, established, pending, needProbe bool
	rx, tx, handshake, targetVersion                     uint64
	stalled, lastProbe, lastHint, next                   time.Time
	delay, stale, probeWait                              time.Duration
	invalidate                                           func()
	probe                                                func() error
	refresh                                              func() error
}

func (p *recoveryPolicy) step(now time.Time, route string, available bool, stats tunnel.Stats, hint bool) {
	changed := p.observed && (p.route != route || p.available != available)
	p.observed = true
	p.route = route
	p.available = available
	handshake := stats.LastHandshakeNano
	if handshake == 0 {
		handshake = stats.LastHandshake * 1000000000
	}
	handshakeProgress := handshake != p.handshake
	progress := stats.RXBytes != p.rx || handshakeProgress
	outgoing := stats.TXBytes != p.tx
	p.rx, p.tx, p.handshake = stats.RXBytes, stats.TXBytes, handshake
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
		p.lastHint = now
		p.pending = false
		p.needProbe = true
		p.delay = 0
	}
	if !available {
		return
	}
	// Explicit network/wakeup hints can identify a new LAN with identical
	// interface, addresses and routes. Debounce their DNS invalidation using
	// wall time so a real suspend is not hidden by CLOCK_MONOTONIC pausing.
	if hint && !changed && (p.lastHint.IsZero() || now.UnixNano()-p.lastHint.UnixNano() >= int64(5*time.Second) || now.UnixNano() < p.lastHint.UnixNano()) {
		p.invalidate()
		p.lastHint = now
	}
	stale := p.stale
	if stale <= 0 {
		stale = 15 * time.Second
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
			p.delay = p.probeWait
			if p.delay < 5*time.Second {
				p.delay = 5 * time.Second
			}
			p.next = now.Add(p.delay)
		}
	}
	if p.pending && !now.Before(p.next) {
		// Submission/open success is not proof of reachability. Only later
		// authenticated RX/handshake progress ends the recovery attempt.
		version := p.targetVersion
		p.refresh()
		if p.targetVersion != version {
			return
		}
		p.delay *= 2
		ceiling := p.probeWait
		if ceiling < 30*time.Second {
			ceiling = 30 * time.Second
		}
		if p.delay > ceiling {
			p.delay = ceiling
		}
		p.next = now.Add(p.delay)
	}
}

// RefreshUnderlay already sent the new target's challenge. Remember its route
// before sampling another epoch, so a successful migration does not provoke a
// second rate-limited challenge and an unnecessary reopen five seconds later.
func (p *recoveryPolicy) submittedTarget(now time.Time, route string, available bool) {
	p.targetVersion++
	p.route = route
	p.observed = true
	p.available = available
	p.invalidate()
	p.lastHint = now
	p.lastProbe = now
	p.pending = true
	p.needProbe = false
	p.delay = p.probeWait
	if p.delay < 5*time.Second {
		p.delay = 5 * time.Second
	}
	p.next = now.Add(p.delay)
}

func startUnderlayRecovery(ctx context.Context, endpoint netip.AddrPort, stale, probeWait time.Duration, stats func() (tunnel.Stats, error), invalidate func(), probe func() error, refresh func(netip.AddrPort) error, discover func(context.Context, netip.AddrPort) (netip.AddrPort, error)) *underlayRecovery {
	ctx, cancel := context.WithCancel(ctx)
	r := &underlayRecovery{cancel: cancel, done: make(chan struct{}), hints: make(chan struct{}, 1), endpoint: endpoint}
	initial, routeErr := protectedRouteFingerprint(endpoint)
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var discoverAfter time.Time
		var policy recoveryPolicy
		tryDiscover := func() bool {
			if discover == nil || time.Now().Before(discoverAfter) {
				return false
			}
			discoverAfter = time.Now().Add(10 * time.Second)
			r.mu.Lock()
			current, revision := r.endpoint, r.revision
			r.mu.Unlock()
			original, originalErr := protectedRouteFingerprint(current)
			lookupCtx, lookupCancel := context.WithTimeout(ctx, 5*time.Second)
			candidate, err := discover(lookupCtx, current)
			lookupCancel()
			if err != nil || !candidate.IsValid() || candidate == current || ctx.Err() != nil {
				return false
			}
			latest, latestErr := protectedRouteFingerprint(current)
			if original != latest || (originalErr == nil) != (latestErr == nil) {
				return false
			}
			if !r.applyCandidate(ctx, candidate, revision, refresh) {
				return false
			}
			targetRoute, targetErr := protectedRouteFingerprint(candidate)
			policy.submittedTarget(time.Now(), targetRoute, targetErr == nil)
			return true
		}
		policy = recoveryPolicy{route: initial, observed: true, available: routeErr == nil, stale: stale, probeWait: probeWait,
			invalidate: func() { r.pathChanges.Add(1); invalidate() },
			probe:      func() error { r.probes.Add(1); return probe() },
			refresh: func() error {
				r.reopens.Add(1)
				if tryDiscover() {
					return nil
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return refresh(netip.AddrPort{})
			}}
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
			if err != nil && policy.established && tryDiscover() {
				continue
			}
			policy.step(time.Now(), route, err == nil, state, hint)
		}
	}()
	return r
}
func (r *underlayRecovery) hint(endpoint netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if endpoint.IsValid() {
		r.endpoint = endpoint
		r.revision++
	}
	select {
	case r.hints <- struct{}{}:
		if !endpoint.IsValid() {
			r.revision++
		}
	default:
	}
}

func (r *underlayRecovery) close() { r.cancel(); <-r.done }
func (r *underlayRecovery) diagnostics() map[string]uint64 {
	return map[string]uint64{"path_changes": r.pathChanges.Load(), "probes": r.probes.Load(), "reopens": r.reopens.Load(), "endpoint_changes": r.endpointChanges.Load()}
}

// A late resolver result cannot override a newer control command or reopen
// sockets after cancellation. Holding the endpoint lock orders the submission
// against manual updates; the runtime separately serializes transport lifetime.
func (r *underlayRecovery) applyCandidate(ctx context.Context, candidate netip.AddrPort, revision uint64, refresh func(netip.AddrPort) error) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil || r.revision != revision || !candidate.IsValid() || candidate == r.endpoint || candidate.Port() != r.endpoint.Port() || candidate.Addr().Zone() != "" || candidate.Addr().IsUnspecified() || candidate.Addr().IsMulticast() {
		return false
	}
	r.endpoint = candidate
	r.revision++
	r.endpointChanges.Add(1)
	refresh(candidate) // Open/submission failure retains this desired target.
	return true
}
