//go:build linux && !android

package desktop

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/tunnel"
)

func TestRecoveryKeepsSocketWhenAuthenticatedPathSurvives(t *testing.T) {
	probes, refreshes, invalidations := 0, 0, 0
	p := recoveryPolicy{invalidate: func() { invalidations++ }, probe: func() error { probes++; return nil }, refresh: func() error { refreshes++; return nil }}
	now := time.Unix(100, 0)
	stats := tunnel.Stats{LastHandshake: 1, RXBytes: 10, TXBytes: 20}
	p.step(now, "gateway-a", true, stats, false)
	p.step(now.Add(time.Second), "gateway-b", true, stats, false)
	for range 100 {
		p.step(now.Add(2*time.Second), "gateway-b", true, stats, true)
	}
	if probes != 1 || refreshes != 0 || invalidations != 1 {
		t.Fatal("duplicate hints disturbed a pending probe", probes, refreshes, invalidations)
	}
	stats.RXBytes++
	stats.LastHandshake++
	p.step(now.Add(3*time.Second), "gateway-b", true, stats, false)
	p.step(now.Add(time.Hour), "gateway-b", true, stats, false)
	if refreshes != 0 || p.pending {
		t.Fatal("authenticated working socket was reopened")
	}
}
func TestRecoveryRetriesUnavailablePathWithoutDestroyingSession(t *testing.T) {
	probes, refreshes, invalidations := 0, 0, 0
	p := recoveryPolicy{invalidate: func() { invalidations++ }, probe: func() error { probes++; return nil }, refresh: func() error { refreshes++; return errors.New("socket open failed") }}
	now := time.Unix(100, 0)
	stats := tunnel.Stats{LastHandshake: 1, RXBytes: 10, TXBytes: 20}
	p.step(now, "a", true, stats, false)
	p.step(now.Add(time.Second), "", false, stats, false)
	for i := 2; i < 1000; i++ {
		p.step(now.Add(time.Duration(i)*time.Second), "", false, stats, true)
	}
	if probes != 0 || refreshes != 0 || invalidations != 1 {
		t.Fatal("offline state repeatedly reopened a socket or DNS")
	}
	p.step(now.Add(1000*time.Second), "b", true, stats, false)
	p.step(now.Add(1005*time.Second), "b", true, stats, false)
	if probes != 1 || refreshes != 1 {
		t.Fatal("restored route was not probed before retry")
	}
	p.step(now.Add(1014*time.Second), "b", true, stats, true)
	if refreshes != 1 {
		t.Fatal("duplicate hint bypassed backoff")
	}
	p.step(now.Add(1015*time.Second), "b", true, stats, false)
	if refreshes != 2 {
		t.Fatal("failed open was not retried")
	}
	// An ACK/handshake from the same cryptographic peer ends all future retries.
	stats.LastHandshake++
	p.step(now.Add(1016*time.Second), "b", true, stats, false)
	p.step(now.Add(2000*time.Second), "b", true, stats, false)
	if refreshes != 2 || p.pending {
		t.Fatal("successful recovery kept reopening the socket")
	}
}
func TestRecoveryPreservesInitialBudgetAndCustomProtocolTimers(t *testing.T) {
	probes, refreshes := 0, 0
	p := recoveryPolicy{stale: 10 * time.Minute, invalidate: func() {}, probe: func() error { probes++; return nil }, refresh: func() error { refreshes++; return nil }}
	now := time.Unix(100, 0)
	p.step(now, "a", true, tunnel.Stats{}, true)
	p.step(now.Add(time.Hour), "b", true, tunnel.Stats{TXBytes: 100}, true)
	if probes != 0 || refreshes != 0 {
		t.Fatal("established recovery took over initial connection")
	}
	stats := tunnel.Stats{LastHandshake: 1, RXBytes: 10, TXBytes: 100}
	p.step(now.Add(2*time.Hour), "b", true, stats, false)
	stats.TXBytes++
	p.step(now.Add(2*time.Hour+time.Second), "b", true, stats, false)
	p.step(now.Add(2*time.Hour+9*time.Minute), "b", true, stats, false)
	if probes != 0 {
		t.Fatal("watchdog ignored custom protocol wait")
	}
	p.step(now.Add(2*time.Hour+11*time.Minute), "b", true, stats, false)
	if probes != 1 || refreshes != 0 {
		t.Fatal("stalled established path was not probed first")
	}
}
func TestRecoveryDefersRouteFlapsUntilProbeRateLimitExpires(t *testing.T) {
	probes := 0
	p := recoveryPolicy{invalidate: func() {}, probe: func() error { probes++; return nil }, refresh: func() error { return nil }}
	now := time.Unix(100, 0)
	stats := tunnel.Stats{LastHandshake: 1}
	p.step(now, "a", true, stats, false)
	p.step(now.Add(time.Second), "b", true, stats, false)
	p.step(now.Add(2*time.Second), "c", true, stats, false)
	stats.LastHandshake++ // Delayed response to the previous route probe.
	p.step(now.Add(3*time.Second), "c", true, stats, false)
	p.step(now.Add(6*time.Second), "c", true, stats, false)
	if probes != 2 {
		t.Fatal("route change during cooldown was lost")
	}
}
func TestProtectedRouteLookupUsesLocalEndpoint(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:9", "[::1]:9"} {
		got, err := protectedRouteFingerprint(netip.MustParseAddrPort(endpoint))
		if err != nil || got == "" {
			t.Fatal("protected loopback route unavailable", endpoint, err)
		}
	}
	if _, err := protectedRouteFingerprint(netip.AddrPort{}); err == nil {
		t.Fatal("invalid endpoint accepted")
	}
}

func TestLateEndpointDiscoveryCannotOverrideNewOwnerIntent(t *testing.T) {
	original := netip.MustParseAddrPort("192.0.2.1:51820")
	candidate := netip.MustParseAddrPort("[2001:db8::1]:51820")
	r := &underlayRecovery{endpoint: original, hints: make(chan struct{}, 1)}
	calls := 0
	refresh := func(got netip.AddrPort) error {
		calls++
		if got != candidate {
			t.Fatal("unexpected candidate")
		}
		return errors.New("open failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r.applyCandidate(ctx, candidate, 0, refresh) || calls != 0 {
		t.Fatal("cancelled DNS result reopened a socket")
	}
	r.hint(netip.MustParseAddrPort("192.0.2.2:51820"))
	if r.applyCandidate(context.Background(), candidate, 0, refresh) || calls != 0 {
		t.Fatal("old DNS result overrode a newer endpoint command")
	}
	if r.applyCandidate(context.Background(), netip.MustParseAddrPort("[2001:db8::1]:99"), 1, refresh) || calls != 0 {
		t.Fatal("DNS changed configured server port")
	}
	if !r.applyCandidate(context.Background(), candidate, 1, refresh) || calls != 1 || r.endpoint != candidate {
		t.Fatal("failed socket open discarded the validated desired endpoint")
	}
}

func TestRecoveryAcceptsTwoHandshakesWithinTheSameSecond(t *testing.T) {
	refreshes := 0
	p := recoveryPolicy{invalidate: func() {}, probe: func() error { return nil }, refresh: func() error { refreshes++; return nil }}
	now := time.Unix(100, 0)
	stats := tunnel.Stats{LastHandshake: 100, LastHandshakeNano: 100000000010}
	p.step(now, "a", true, stats, false)
	p.step(now.Add(time.Millisecond), "b", true, stats, false)
	stats.LastHandshakeNano++
	p.step(now.Add(2*time.Millisecond), "b", true, stats, false)
	p.step(now.Add(6*time.Second), "b", true, stats, false)
	if refreshes != 0 || p.pending {
		t.Fatal("coarse seconds lost a valid authenticated probe")
	}
}
func TestWakeupHintInvalidatesDNSWithoutRouteChange(t *testing.T) {
	invalidations := 0
	p := recoveryPolicy{invalidate: func() { invalidations++ }, probe: func() error { return nil }, refresh: func() error { return nil }}
	now := time.Unix(100, 0)
	stats := tunnel.Stats{LastHandshake: 1}
	p.step(now, "same-lan-shape", true, stats, false)
	p.step(now.Add(time.Second), "same-lan-shape", true, stats, true)
	for range 50 {
		p.step(now.Add(2*time.Second), "same-lan-shape", true, stats, true)
	}
	if invalidations != 1 {
		t.Fatal("duplicate hints repeatedly replaced DNS")
	}
	p.step(now.Add(time.Hour), "same-lan-shape", true, stats, true)
	if invalidations != 2 {
		t.Fatal("wakeup reused stale real DNS on an indistinguishable LAN")
	}
}

func TestRecoveryWaitsForLongerConfiguredHandshakeBudget(t *testing.T) {
	refreshes := 0
	p := recoveryPolicy{probeWait: time.Minute, invalidate: func() {}, probe: func() error { return nil }, refresh: func() error { refreshes++; return nil }}
	now := time.Unix(100, 0)
	stats := tunnel.Stats{LastHandshake: 1}
	p.step(now, "a", true, stats, false)
	p.step(now.Add(time.Second), "b", true, stats, false)
	p.step(now.Add(30*time.Second), "b", true, stats, false)
	if refreshes != 0 {
		t.Fatal("configured handshake wait was shortened")
	}
	p.step(now.Add(61*time.Second), "b", true, stats, false)
	p.step(now.Add(92*time.Second), "b", true, stats, false)
	if refreshes != 1 {
		t.Fatal("retry backoff violated the configured minimum")
	}
}

func TestSuccessfulTargetSubmissionDoesNotProvokeAnotherSocketReopen(t *testing.T) {
	probes, reopens := 0, 0
	p := recoveryPolicy{invalidate: func() {}, probe: func() error { probes++; return nil }, refresh: func() error { reopens++; return nil }}
	now := time.Unix(100, 0)
	stats := tunnel.Stats{LastHandshake: 100, LastHandshakeNano: 100000000001}
	p.step(now, "a", true, stats, false)
	p.submittedTarget(now.Add(time.Second), "new-address", true)
	stats.LastHandshakeNano++
	p.step(now.Add(2*time.Second), "new-address", true, stats, false)
	p.step(now.Add(8*time.Second), "new-address", true, stats, false)
	if probes != 0 || reopens != 0 || p.pending {
		t.Fatal("fresh target handshake was probed/opened again", probes, reopens)
	}
}
