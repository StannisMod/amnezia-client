package engine

import (
	"context"
	"encoding/json"
	"runtime/pprof"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type diagnosticOutbound struct{ adapter.Outbound }

func TestStalledDNSProfileIsBoundedAndExcludesApplicationLabels(t *testing.T) {
	const secret = "private-query-identity.invalid"
	var snapshot string
	pprof.Do(context.Background(), pprof.Labels("private-domain", secret), func(context.Context) {
		snapshot = stalledDNSStacks()
	})
	if !strings.Contains(snapshot, "goroutine profile:") || len(snapshot) > 128*1024 {
		t.Fatal("invalid bounded goroutine profile")
	}
	if strings.Contains(snapshot, secret) || strings.Contains(snapshot, "# labels:") {
		t.Fatal("application labels escaped into diagnostic profile")
	}
}

func (diagnosticOutbound) Tag() string { return "vpn" }

func TestOwnerDiagnosticsDistinguishMissingIdentityWithoutRetainingIt(t *testing.T) {
	var d Diagnostics
	m := adapter.InboundContext{Inbound: TUNTag, Network: "tcp", Domain: "private-application.invalid", Destination: M.ParseSocksaddr("192.0.2.39:8443")}
	for _, owner := range []*adapter.ConnectionOwner{nil, {UserId: -1}, {UserId: 0}, {UserId: 10362}} {
		m.ProcessInfo = owner
		d.record(m, nil, diagnosticOutbound{})
	}
	snapshot := d.Snapshot()
	if snapshot.UnknownOwner != 2 || !snapshot.LastOwnerKnown || snapshot.VPN != 4 {
		t.Fatalf("wrong ownership classification: %+v", snapshot)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{"10362", "192.0.2.39", "private-application.invalid"} {
		if strings.Contains(string(raw), sensitive) {
			t.Fatal("owner diagnostics retained flow identity", sensitive)
		}
	}
	// A later unknown flow must clear the previous known-owner indication.
	m.ProcessInfo = nil
	d.record(m, nil, diagnosticOutbound{})
	snapshot = d.Snapshot()
	if snapshot.UnknownOwner != 3 || snapshot.LastOwnerKnown {
		t.Fatal("unknown flow inherited previous ownership", snapshot)
	}
	m.Inbound = "another-inbound"
	d.record(m, nil, diagnosticOutbound{})
	m.Inbound = TUNTag
	d.record(m, nil, nil)
	if d.Snapshot() != snapshot {
		t.Fatal("uncounted flow changed ownership diagnostics")
	}
}
