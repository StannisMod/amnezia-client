package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigIPv6JournalRejectsImpossibleOwnership(t *testing.T) {
	for _, value := range []configIPv6Journal{
		{CIDR: "fd77::1/64"}, {CIDR: "fd77::1/64", WasPresent: true},
		{CIDR: "fd77::1/64", AddIntent: true}, {CIDR: "fd77::1/64", AddIntent: true, Applied: true},
		{CIDR: "fd77::1/64", WasPresent: true, Applied: true}, {CIDR: "fd77::1/64", AddIntent: true, Ambiguous: true},
	} {
		if !configIPv6JournalOK(&value) {
			t.Fatal("valid ownership rejected", value)
		}
	}
	for _, value := range []configIPv6Journal{
		{CIDR: "fd77::1/128"}, {CIDR: "10.8.0.1/24"}, {CIDR: "fe80::1/64"}, {CIDR: "FD77::1/64"},
		{CIDR: "fd77::1/64", WasPresent: true, AddIntent: true}, {CIDR: "fd77::1/64", Ambiguous: true},
		{CIDR: "fd77::1/64", Applied: true}, {CIDR: "fd77::1/64", AddIntent: true, Ambiguous: true, Applied: true},
	} {
		if configIPv6JournalOK(&value) {
			t.Fatal("impossible ownership accepted", value)
		}
	}
}

func TestConfigIPv6JournalBindsAddressToExactMigrationPlan(t *testing.T) {
	original := []byte(migrationConfig())
	plan, err := planIPv6Config(original, "fd77::1/64")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	transaction, err := beginPreparedConfigTransaction(path, original, plan.Config, func(journal *configJournal) error {
		journal.IPv6 = &configIPv6Journal{CIDR: "fd77::1/64", WasPresent: true}
		journal.NativeOriginal = []byte("synthetic native configuration")
		journal.NativeHash = configHash(journal.NativeOriginal)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction.close()
	resumed, err := resumeConfigTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	resumed.close()
	raw, err := os.ReadFile(path + ".amnezia-journal")
	if err != nil {
		t.Fatal(err)
	}
	var journal configJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		t.Fatal(err)
	}
	journal.IPv6.CIDR = "fd88::1/64"
	raw, err = json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".amnezia-journal", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if resumed, err := resumeConfigTransaction(path); err == nil {
		resumed.close()
		t.Fatal("address mutation detached from plan accepted")
	}
	assertConfig(t, path, plan.Config)
}
