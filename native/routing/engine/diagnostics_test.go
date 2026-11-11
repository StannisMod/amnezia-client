package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type diagnosticOutbound struct{ adapter.Outbound }

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
