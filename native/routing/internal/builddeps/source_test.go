package builddeps

import (
	"encoding/json"
	"testing"
)

func TestLinkedSourceMatchesLock(t *testing.T) {
	var lock Pins
	if err := json.Unmarshal(Lock, &lock); err != nil {
		t.Fatal(err)
	}
	if len(lock.Profiles) != 2 {
		t.Fatal("incomplete dependency scopes")
	}
	info := Source()
	if allowReproduction() {
		if info.Mode != "reproduction" {
			t.Fatal("diagnostic build claims fixed source")
		}
		return
	}
	if (info.Mode != "fixed" && !(allowRaceDependency() && info.Mode == "race-diagnostic")) || info.FixID != lock.FixID {
		t.Fatalf("unverified linked TCP source: %+v", info)
	}
	pin, ok := lock.Profiles[info.Profile]
	if !ok || info.UpstreamCommit != pin.UpstreamCommit || info.UpstreamVersion != pin.UpstreamVersion || info.Commit != pin.Commit {
		t.Fatal("wrong linked TCP baseline")
	}
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
}
