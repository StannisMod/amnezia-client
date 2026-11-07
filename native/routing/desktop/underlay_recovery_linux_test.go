//go:build linux && !android

package desktop

import (
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
