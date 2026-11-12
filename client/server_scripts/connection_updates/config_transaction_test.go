package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func transactionFixture(t *testing.T) (string, []byte, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg0.conf")
	original, candidate := []byte("original private key and peers\n"), []byte("same keys with migrated addresses\n")
	if err := os.WriteFile(path, original, 0640); err != nil {
		t.Fatal(err)
	}
	return path, original, candidate
}
func assertConfig(t *testing.T, path string, expected []byte) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("unexpected config %q: %v", actual, err)
	}
}
func TestConfigTransactionCommitAndRollback(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		path, original, candidate := transactionFixture(t)
		transaction, err := beginConfigTransaction(path, original, candidate)
		if err != nil {
			t.Fatal(err)
		}
		assertConfig(t, path, candidate)
		info, err := os.Stat(path + ".amnezia-journal")
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("journal is not private", err)
		}
		if _, err := beginConfigTransaction(path, candidate, original); err == nil {
			t.Fatal("concurrent writer acquired lock")
		}
		if err := transaction.finish(rollback); err != nil {
			t.Fatal(err)
		}
		expected := candidate
		if rollback {
			expected = original
		}
		assertConfig(t, path, expected)
		info, _ = os.Stat(path)
		if info.Mode().Perm() != 0640 {
			t.Fatal("configuration mode changed")
		}
		if _, err := os.Stat(path + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("completed journal retained", err)
		}
		if transaction.finish(rollback) == nil {
			t.Fatal("closed transaction accepted")
		}
	}
}
func TestConfigTransactionRejectsStaleOrConflictingWrites(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	if _, err := beginConfigTransaction(path, []byte("stale"), candidate); !errors.Is(err, errConfigConflict) {
		t.Fatal("stale write accepted", err)
	}
	assertConfig(t, path, original)
	transaction, err := beginConfigTransaction(path, original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte("independent later server edit\n")
	if err := os.WriteFile(path, changed, 0640); err != nil {
		t.Fatal(err)
	}
	if err := transaction.finish(true); !errors.Is(err, errConfigConflict) {
		t.Fatal("rollback overwrote conflict", err)
	}
	assertConfig(t, path, changed)
	if _, err := os.Stat(path + ".amnezia-journal"); err != nil {
		t.Fatal("conflict lost recovery journal", err)
	}
}
func TestConfigTransactionInterruptedProcess(t *testing.T) {
	if path := os.Getenv("AMNEZIA_CONFIG_TRANSACTION_CHILD"); path != "" {
		if _, err := beginConfigTransaction(path, []byte("original private key and peers\n"), []byte("same keys with migrated addresses\n")); err != nil {
			os.Exit(31)
		}
		os.Exit(23) // Deliberately bypass all defers; the OS must release flock.
	}
	path, original, candidate := transactionFixture(t)
	command := exec.Command(os.Args[0], "-test.run=^TestConfigTransactionInterruptedProcess$")
	command.Env = append(os.Environ(), "AMNEZIA_CONFIG_TRANSACTION_CHILD="+path)
	err := command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatal("child did not stop after staging", err)
	}
	assertConfig(t, path, candidate)
	if _, err := beginConfigTransaction(path, candidate, original); err == nil {
		t.Fatal("pending journal overwritten")
	}
	transaction, err := resumeConfigTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.finish(true); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path, original)
}
func TestConfigTransactionRejectsUnsafePathsAndJournal(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "parent-symlink", "journal-symlink", "corrupt-journal", "writable-parent"} {
		t.Run(kind, func(t *testing.T) {
			path, original, candidate := transactionFixture(t)
			target := path
			switch kind {
			case "symlink":
				target = path + "-link"
				if err := os.Symlink(path, target); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+"-link"); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(filepath.Dir(path), link); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(link, "wg0.conf")
			case "journal-symlink":
				if err := os.Symlink(path, path+".amnezia-journal"); err != nil {
					t.Fatal(err)
				}
			case "corrupt-journal":
				if err := os.WriteFile(path+".amnezia-journal", []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
				if transaction, err := resumeConfigTransaction(path); err == nil {
					transaction.close()
					t.Fatal("corrupt journal accepted")
				}
			case "writable-parent":
				if err := os.Chmod(filepath.Dir(path), 0777); err != nil {
					t.Fatal(err)
				}
			}
			if transaction, err := beginConfigTransaction(target, original, candidate); err == nil {
				transaction.close()
				t.Fatal("unsafe transaction accepted")
			}
			assertConfig(t, path, original)
		})
	}
}

func TestConfigTransactionRecoversUnappliedJournal(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	transaction, err := beginConfigTransaction(path, original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct the durable state after journal persistence but before replace.
	if err := os.WriteFile(path, original, 0640); err != nil {
		t.Fatal(err)
	}
	transaction.close()
	resumed, err := resumeConfigTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.finish(true); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path, original)
	if _, err := os.Stat(path + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unapplied journal retained", err)
	}
}

func TestConfigTransactionPreservesIndependentModeChange(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	transaction, err := beginConfigTransaction(path, original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := transaction.finish(true); !errors.Is(err, errConfigConflict) {
		t.Fatal("independent permissions change overwritten", err)
	}
	assertConfig(t, path, candidate)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("independent permissions not preserved", err)
	}
}

func TestConfigTransactionCommandBindsOperation(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	paths := map[string]string{"amnezia-wireguard": path}
	invoke := func(request configTransactionRequest) (map[string]any, error) {
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		err = configTransactionCommand(bytes.NewReader(raw), &output, paths)
		var result map[string]any
		if output.Len() != 0 {
			if e := json.Unmarshal(output.Bytes(), &result); e != nil {
				t.Fatal(e)
			}
		}
		return result, err
	}
	staged, err := invoke(configTransactionRequest{Action: "stage", Container: "amnezia-wireguard", Expected: original, Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	operation := staged["operation"].(string)
	if !configOperationOK(operation) {
		t.Fatal("invalid operation identifier")
	}
	for _, wrong := range []configTransactionRequest{
		{Action: "rollback", Container: "amnezia-wireguard", Operation: strings.Repeat("0", 64)},
		{Action: "rollback", Container: "amnezia-wireguard", Operation: operation, Candidate: candidate},
		{Action: "commit", Container: "foreign", Operation: operation},
		{Action: "unknown", Container: "amnezia-wireguard"},
	} {
		if result, err := invoke(wrong); err == nil || result != nil {
			t.Fatal("invalid request accepted")
		}
		assertConfig(t, path, candidate)
	}
	status, err := invoke(configTransactionRequest{Action: "status", Container: "amnezia-wireguard"})
	if err != nil || status["state"] != "candidate" || status["operation"] != operation {
		t.Fatal("pending operation lost", err)
	}
	if result, err := invoke(configTransactionRequest{Action: "rollback", Container: "amnezia-wireguard", Operation: operation}); err != nil || result["operation"] != operation {
		t.Fatal("rollback failed", err)
	}
	assertConfig(t, path, original)
	if _, err := invoke(configTransactionRequest{Action: "rollback", Container: "amnezia-wireguard", Operation: operation}); err == nil {
		t.Fatal("completed operation replayed")
	}
	staged, err = invoke(configTransactionRequest{Action: "stage", Container: "amnezia-wireguard", Expected: original, Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	if staged["operation"] == operation {
		t.Fatal("operation identifier reused")
	}
	if _, err := invoke(configTransactionRequest{Action: "commit", Container: "amnezia-wireguard", Operation: staged["operation"].(string)}); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path, candidate)
}

func TestNativeSnapshotIntegrityAndPrivateJournal(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	native := []byte("synthetic native protocol baseline\n")
	transaction, err := beginPreparedConfigTransaction(path, original, candidate, func(journal *configJournal) error {
		journal.NativeOriginal = native
		journal.NativeHash = configHash(native)
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
	if !bytes.Equal(resumed.journal.NativeOriginal, native) {
		t.Fatal("native snapshot lost")
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
	journal.NativeOriginal = []byte("different native configuration\n")
	raw, err = json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".amnezia-journal", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if resumed, err := resumeConfigTransaction(path); err == nil {
		resumed.close()
		t.Fatal("corrupt native snapshot accepted")
	}
	assertConfig(t, path, candidate)
}

func TestNativeWriteIntentJournalInvariant(t *testing.T) {
	native := []byte("private native snapshot\n")
	base := configJournal{NativeOriginal: native, NativeHash: configHash(native)}
	if !configNativeJournalOK(base) {
		t.Fatal("staged snapshot rejected")
	}
	applied := base
	applied.NativeApplied = true
	if configNativeJournalOK(applied) {
		t.Fatal("applied state without write intent accepted")
	}
	applied.NativeWriteIntent = true
	if !configNativeJournalOK(applied) {
		t.Fatal("applied write intent rejected")
	}
	pending := base
	pending.NativeWriteIntent = true
	if !configNativeJournalOK(pending) {
		t.Fatal("interrupted native write rejected")
	}
	if configNativeJournalOK(configJournal{NativeWriteIntent: true}) {
		t.Fatal("write intent without backup accepted")
	}
}

func TestLiveStateCheckRefusesPendingAndMismatchedFile(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	txn, err := beginConfigTransaction(path, original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	txn.close()
	invoke := func(req configTransactionRequest) error {
		raw, _ := json.Marshal(req)
		var output bytes.Buffer
		return configTransactionCommand(bytes.NewReader(raw), &output, map[string]string{"amnezia-wireguard": path})
	}
	if err := invoke(configTransactionRequest{Action: "check-live", Container: "amnezia-wireguard", Expected: candidate}); err == nil {
		t.Fatal("pending file reported committed")
	}
	resumed, err := resumeConfigTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.finish(true); err != nil {
		t.Fatal(err)
	}
	resumed.close()
	if err := invoke(configTransactionRequest{Action: "check-live", Container: "amnezia-wireguard", Expected: candidate}); err == nil {
		t.Fatal("mismatched file reported current")
	}
	if err := invoke(configTransactionRequest{Action: "capabilities", Container: "amnezia-wireguard"}); err != nil {
		t.Fatal(err)
	}
	if err := invoke(configTransactionRequest{Action: "capabilities", Container: "amnezia-wireguard", Expected: original}); err == nil {
		t.Fatal("capability query accepted unrelated input")
	}
}

func TestConfigHelperAtomicInstallation(t *testing.T) {
	for _, blocked := range []string{"", "config", "startup", "symlink", "foreign", "busy"} {
		t.Run(blocked, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "config-helper")
			config := filepath.Join(dir, "wg0.conf")
			startup := filepath.Join(dir, "start.sh")
			old, next := []byte("verified old executable"), []byte("verified candidate executable")
			if err := os.WriteFile(target, old, 0700); err != nil {
				t.Fatal(err)
			}
			switch blocked {
			case "config":
				os.WriteFile(config+".amnezia-journal", []byte("pending"), 0600)
			case "startup":
				os.WriteFile(startup+".amnezia-journal", []byte("pending"), 0600)
			case "symlink":
				os.Remove(target)
				os.Symlink(config, target)
			case "foreign":
				os.WriteFile(target, []byte("foreign executable"), 0700)
			case "busy":
				lock, err := lockConfig(config)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			}
			err := installConfigHelper(config, startup, target, next, configHash(old))
			if blocked != "" {
				if err == nil {
					t.Fatal("unsafe replacement accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertConfig(t, target, next)
			if err := installConfigHelper(config, startup, target, next, configHash(old)); err != nil {
				t.Fatalf("lost-response retry: %v", err)
			}
			if err := installConfigHelper(config, startup, target, old, configHash(old)); err == nil {
				t.Fatal("stale expected hash accepted")
			}
		})
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "helper")
	if err := installConfigHelper(filepath.Join(dir, "wg0.conf"), filepath.Join(dir, "start.sh"), target, []byte("candidate"), ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("helper permissions")
	}
}

func TestOwnedHelperInstallationRecovery(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "helper")
	config := filepath.Join(dir, "wg.conf")
	startup := filepath.Join(dir, "start.sh")
	old, next := []byte("first verified candidate"), []byte("second verified candidate")
	install := func(data []byte) error { return installOwnedConfigHelper(config, startup, target, data) }
	if err := install(old); err != nil {
		t.Fatal(err)
	}
	if err := install(next); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, target, next)
	// Model a crash after durable intent but before or after executable rename.
	for _, published := range []bool{false, true} {
		current := old
		if published {
			current = next
		}
		if err := os.WriteFile(target, current, 0700); err != nil {
			t.Fatal(err)
		}
		receipt := map[string]any{"version": 1, "installed": configHash(old), "candidate": configHash(next)}
		raw, _ := json.Marshal(receipt)
		if err := os.WriteFile(target+".amnezia-owner", raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := install(next); err != nil {
			t.Fatalf("recovery published=%v: %v", published, err)
		}
		assertConfig(t, target, next)
	}
	if err := os.WriteFile(target, []byte("foreign"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := install(next); err == nil {
		t.Fatal("foreign replacement adopted")
	}
	assertConfig(t, target, []byte("foreign"))
	if err := os.Remove(target + ".amnezia-owner"); err != nil {
		t.Fatal(err)
	}
	if err := install(next); err == nil {
		t.Fatal("unowned existing helper adopted")
	}
}

func TestRollbackEvidenceValidationAndV5Upgrade(t *testing.T) {
	native := []byte("native snapshot")
	journal := configJournal{Version: 6, NativeOriginal: native, NativeHash: configHash(native), NativeRollbackHash: strings.Repeat("a", 64)}
	if !configNativeJournalOK(journal) {
		t.Fatal("valid rollback evidence refused")
	}
	journal.Version = 5
	if configNativeJournalOK(journal) {
		t.Fatal("rollback evidence accepted in old format")
	}
	journal.Version = 6
	journal.NativeRollbackHash = "bad"
	if configNativeJournalOK(journal) {
		t.Fatal("invalid rollback digest accepted")
	}
	journal.NativeRollbackHash = strings.Repeat("a", 64)
	journal.NativeOriginal = nil
	journal.NativeHash = ""
	if configNativeJournalOK(journal) {
		t.Fatal("rollback evidence without snapshot accepted")
	}
	path, original, candidate := transactionFixture(t)
	transaction, err := beginConfigTransaction(path, original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	old := transaction.journal
	old.Version = 5
	raw, _ := json.Marshal(old)
	if err := os.WriteFile(path+".amnezia-journal", raw, 0600); err != nil {
		t.Fatal(err)
	}
	transaction.close()
	resumed, err := resumeConfigTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.journal.Version != 5 {
		t.Fatal("old journal not loaded")
	}
	if err := resumed.saveJournal(); err != nil {
		t.Fatal(err)
	}
	resumed.close()
	upgraded, err := resumeConfigTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.close()
	if upgraded.journal.Version != 6 {
		t.Fatal("journal not upgraded durably")
	}
}

func TestOwnedHelperRestorePreservesKnownPendingJournal(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	dir := filepath.Dir(path)
	target := filepath.Join(dir, "helper")
	startup := filepath.Join(dir, "start.sh")
	old, next := []byte("owned old helper"), []byte("verified replacement helper")
	if err := installOwnedConfigHelper(path, startup, target, old); err != nil {
		t.Fatal(err)
	}
	pending, err := beginConfigTransaction(path, original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	pending.close()
	raw, err := os.ReadFile(path + ".amnezia-journal")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, next); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, target, next)
	assertConfig(t, path, candidate)
	assertConfig(t, path+".amnezia-journal", raw)
	var journal map[string]any
	json.Unmarshal(raw, &journal)
	journal["version"] = 99
	unknown, _ := json.Marshal(journal)
	if err := os.WriteFile(path+".amnezia-journal", unknown, 0600); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, old); err == nil {
		t.Fatal("unknown pending format replaced existing helper")
	}
	assertConfig(t, target, next)
	assertConfig(t, path+".amnezia-journal", unknown)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, old); err == nil {
		t.Fatal("unknown pending format adopted")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("helper published over unknown journal")
	}
	assertConfig(t, path, candidate)
	assertConfig(t, path+".amnezia-journal", unknown)
	if err := os.WriteFile(path+".amnezia-journal", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, next); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path+".amnezia-journal", raw)
}

func TestUnownedPendingJournalCannotBeAdoptedByRetry(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	dir := filepath.Dir(path)
	target := filepath.Join(dir, "helper")
	startup := filepath.Join(dir, "start.sh")
	pending, err := beginConfigTransaction(path, original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	pending.close()
	raw, _ := os.ReadFile(path + ".amnezia-journal")
	for i := 0; i < 2; i++ {
		if err := installOwnedConfigHelper(path, startup, target, []byte("verified candidate")); err == nil {
			t.Fatal("unowned journal adopted")
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unowned helper published")
		}
		assertConfig(t, path, candidate)
		assertConfig(t, path+".amnezia-journal", raw)
	}
}

func TestHelperRestoreRejectsLinkedPendingJournal(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	dir := filepath.Dir(path)
	target := filepath.Join(dir, "helper")
	startup := filepath.Join(dir, "start.sh")
	if err := installOwnedConfigHelper(path, startup, target, []byte("owned helper")); err != nil {
		t.Fatal(err)
	}
	pending, err := beginConfigTransaction(path, original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	pending.close()
	journal := path + ".amnezia-journal"
	other := filepath.Join(dir, "linked-journal")
	if err := os.Link(journal, other); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, []byte("replacement")); err == nil {
		t.Fatal("linked pending journal accepted")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("helper published with linked journal")
	}
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path, candidate)
}

func TestOwnedHelperPreservesStartupJournalAndRejectsNativeRole(t *testing.T) {
	path, _, _ := transactionFixture(t)
	dir := filepath.Dir(path)
	target := filepath.Join(dir, "helper")
	startup := filepath.Join(dir, "start.sh")
	if err := installOwnedConfigHelper(path, startup, target, []byte("first helper")); err != nil {
		t.Fatal(err)
	}
	original, candidate := []byte("#!/bin/sh\n# original startup\n"), []byte("#!/bin/sh\n# staged startup\n")
	if err := os.WriteFile(startup, original, 0700); err != nil {
		t.Fatal(err)
	}
	pending, err := beginConfigTransaction(startup, original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	pending.close()
	raw, _ := os.ReadFile(startup + ".amnezia-journal")
	if err := installOwnedConfigHelper(path, startup, target, []byte("second helper")); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, startup, candidate)
	assertConfig(t, startup+".amnezia-journal", raw)
	pending, err = resumeConfigTransaction(startup)
	if err != nil {
		t.Fatal(err)
	}
	pending.journal.NativeOriginal = []byte("native snapshot must not be in startup journal")
	pending.journal.NativeHash = configHash(pending.journal.NativeOriginal)
	if err := pending.saveJournal(); err != nil {
		t.Fatal(err)
	}
	pending.close()
	if err := installOwnedConfigHelper(path, startup, target, []byte("third helper")); err == nil {
		t.Fatal("native startup journal accepted")
	}
	assertConfig(t, target, []byte("second helper"))
	assertConfig(t, startup, candidate)
}
