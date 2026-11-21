package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

func TestAtomicPublicationSurvivesExitWithoutCleanup(t *testing.T) {
	if directory := os.Getenv("AMNEZIA_ATOMIC_PUBLICATION_CHILD"); directory != "" {
		source, target := filepath.Join(directory, "prepared"), filepath.Join(directory, "published")
		if err := os.WriteFile(source, []byte("complete private publication"), 0600); err != nil {
			os.Exit(31)
		}
		file, err := os.Open(source)
		if err != nil {
			os.Exit(32)
		}
		err = file.Sync()
		file.Close()
		if err != nil {
			os.Exit(33)
		}
		if os.Getenv("AMNEZIA_ATOMIC_PUBLICATION_LEGACY") == "1" {
			err = os.Link(source, target)
		} else {
			err = renameConfigNoReplace(source, target)
		}
		if err != nil {
			os.Exit(34)
		}
		os.Exit(23) // No defer, directory sync or temporary-file cleanup can run.
	}
	for _, legacy := range []bool{false, true} {
		directory := t.TempDir()
		command := exec.Command(os.Args[0], "-test.run=^TestAtomicPublicationSurvivesExitWithoutCleanup$")
		command.Env = append(os.Environ(), "AMNEZIA_ATOMIC_PUBLICATION_CHILD="+directory)
		if legacy {
			command.Env = append(command.Env, "AMNEZIA_ATOMIC_PUBLICATION_LEGACY=1")
		}
		err := command.Run()
		var exited *exec.ExitError
		if !errors.As(err, &exited) || exited.ExitCode() != 23 {
			t.Fatal("publication child failed", err)
		}
		target := filepath.Join(directory, "published")
		assertConfig(t, target, []byte("complete private publication"))
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		links := info.Sys().(*syscall.Stat_t).Nlink
		_, sourceErr := os.Lstat(filepath.Join(directory, "prepared"))
		if legacy {
			if links != 2 || sourceErr != nil {
				t.Fatal("legacy control did not expose double-link window")
			}
		} else if links != 1 || !errors.Is(sourceErr, os.ErrNotExist) {
			t.Fatal("atomic publication left a temporary alias")
		}
	}
}

func TestExclusivePublicationRacePreservesWinner(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "published")
	type result struct {
		data []byte
		err  error
	}
	results := make(chan result, 12)
	for i := 0; i < 12; i++ {
		go func(value byte) {
			data := bytes.Repeat([]byte{value}, 256<<10)
			err := writeConfigAtomic(target, data, 0600, os.Geteuid(), os.Getegid(), true)
			results <- result{data, err}
		}(byte(i + 1))
	}
	winners := 0
	var winner []byte
	for i := 0; i < 12; i++ {
		r := <-results
		if r.err == nil {
			winners++
			winner = r.data
		} else if !errors.Is(r.err, os.ErrExist) {
			t.Fatal("unexpected publication error", r.err)
		}
	}
	if winners != 1 {
		t.Fatal("exclusive publication did not choose exactly one writer")
	}
	assertConfig(t, target, winner)
	info, err := os.Stat(target)
	if err != nil || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("published inode has aliases")
	}
	remaining, err := filepath.Glob(filepath.Join(directory, ".amnezia-config-*"))
	if err != nil || len(remaining) != 0 {
		t.Fatal("finished writers left temporary files")
	}
	before := info
	if err := writeConfigAtomic(target, []byte("foreign replacement"), 0700, os.Geteuid(), os.Getegid(), true); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing target was replaceable")
	}
	after, err := os.Stat(target)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0600 {
		t.Fatal("losing writer changed existing inode")
	}
	assertConfig(t, target, winner)
}

func TestDiscardStageRequiresUnappliedOriginalAndMatchingOperation(t *testing.T) {
	for _, scenario := range []string{"original", "candidate", "foreign", "intent", "applied", "wrong-operation", "file-only", "mode-change"} {
		t.Run(scenario, func(t *testing.T) {
			path, original, candidate := transactionFixture(t)
			txn, err := beginPreparedConfigTransaction(path, original, candidate, func(j *configJournal) error {
				if scenario != "file-only" {
					j.NativeOriginal = []byte("native snapshot")
					j.NativeHash = configHash(j.NativeOriginal)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			operation := txn.journal.Operation
			if scenario == "intent" {
				txn.journal.NativeWriteIntent = true
			}
			if scenario == "applied" {
				txn.journal.NativeWriteIntent = true
				txn.journal.NativeApplied = true
			}
			if err := txn.saveJournal(); err != nil {
				t.Fatal(err)
			}
			txn.close()
			current := original
			if scenario == "candidate" {
				current = candidate
			}
			if scenario == "foreign" {
				current = []byte("independent edit")
			}
			if err := os.WriteFile(path, current, 0640); err != nil {
				t.Fatal(err)
			}
			if scenario == "mode-change" {
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path + ".amnezia-journal")
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "wrong-operation" {
				operation = strings.Repeat("0", 64)
			}
			raw, err := json.Marshal(configTransactionRequest{Action: "discard-stage", Container: "amnezia-wireguard", Operation: operation})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err = configTransactionCommand(bytes.NewReader(raw), &output, map[string]string{"amnezia-wireguard": path})
			assertConfig(t, path, current)
			if scenario == "original" {
				if err != nil {
					t.Fatal(err)
				}
				var result map[string]any
				if err := json.Unmarshal(output.Bytes(), &result); err != nil || result["discardedStage"] != true {
					t.Fatal("missing discard receipt", err)
				}
				if _, err := os.Lstat(path + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("discarded stage journal remains")
				}
			} else {
				if err == nil || output.Len() != 0 {
					t.Fatal("unsafe discard accepted")
				}
				assertConfig(t, path+".amnezia-journal", before)
			}
		})
	}
}

func TestClientTableCASPreservesForeignDataAndMetadata(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	table := filepath.Join(filepath.Dir(path), "clientsTable")
	before := []byte("[ {\"clientId\":\"first\",\"unknown\":{\"preserve\":true}} ]\n")
	after := []byte("[]\n")
	if err := os.WriteFile(table, before, 0640); err != nil {
		t.Fatal(err)
	}
	invoke := func(action string, expected, replacement []byte) error {
		raw, err := json.Marshal(configTransactionRequest{Action: action, Container: "amnezia-wireguard", Expected: expected, Candidate: replacement})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		err = configTransactionCommand(bytes.NewReader(raw), &output, map[string]string{"amnezia-wireguard": path})
		if err == nil {
			var result map[string]any
			if json.Unmarshal(output.Bytes(), &result) != nil || result["current"] != true {
				t.Fatal("invalid table receipt")
			}
		}
		return err
	}
	if err := invoke("check-client-table", before, nil); err != nil {
		t.Fatal(err)
	}
	pending, err := beginConfigTransaction(path, original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	pending.close()
	if err := invoke("replace-client-table", before, after); err == nil {
		t.Fatal("table mutated during pending peer transaction")
	}
	assertConfig(t, table, before)
	pending, err = resumeConfigTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.finish(true); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{nil, []byte("null"), []byte("{}"), []byte("[null]"), []byte("[1]"), []byte("[{}] trailing")} {
		if err := invoke("replace-client-table", before, invalid); err == nil {
			t.Fatal("invalid metadata accepted")
		}
		assertConfig(t, table, before)
	}
	foreign := []byte("[{\"clientId\":\"independent\"}]")
	if err := os.WriteFile(table, foreign, 0640); err != nil {
		t.Fatal(err)
	}
	if err := invoke("replace-client-table", before, after); !errors.Is(err, errConfigConflict) {
		t.Fatal("stale snapshot accepted", err)
	}
	assertConfig(t, table, foreign)
	if err := invoke("replace-client-table", foreign, after); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, table, after)
	info, err := os.Stat(table)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatal("metadata permissions changed", err)
	}
	if err := invoke("check-client-table", after, nil); err != nil {
		t.Fatal("lost reply reconciliation failed", err)
	}
	if err := invoke("replace-client-table", foreign, after); !errors.Is(err, errConfigConflict) {
		t.Fatal("stale operation replay accepted", err)
	}
	if err := os.Link(table, table+".foreign"); err != nil {
		t.Fatal(err)
	}
	if err := invoke("replace-client-table", after, before); err == nil {
		t.Fatal("hardlinked metadata accepted")
	}
	assertConfig(t, table, after)
}

func TestNativeReceiptIsDurableBeforeJournalRemovalAndAckBound(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	id := strings.Repeat("a", 64)
	receipts := configReceipts{Version: 1, Records: map[string]configReceipt{id: {OriginalHash: configHash(original), CandidateHash: configHash(candidate), State: "pending"}}}
	if err := writeConfigReceipts(path, receipts); err != nil {
		t.Fatal(err)
	}
	txn, err := beginPreparedConfigTransaction(path, original, candidate, func(j *configJournal) error {
		j.NativeOriginal = []byte("synthetic native snapshot")
		j.NativeHash = configHash(j.NativeOriginal)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	txn.journal.NativeWriteIntent = true
	txn.journal.NativeApplied = true
	if err := txn.saveJournal(); err != nil {
		t.Fatal(err)
	}
	// Deterministic interruption immediately after receipt publication, with the
	// journal still present. This tests storage ordering, not native application.
	if err := txn.completeReceipts(false); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path + ".amnezia-receipts")
	if err != nil {
		t.Fatal(err)
	}
	nativeOperation := txn.journal.Operation
	txn.close()
	loaded, err := readConfigReceipts(path)
	if err != nil || loaded.Records[id].State != "committed" || loaded.Records[id].NativeOperation != nativeOperation {
		t.Fatal("durable terminal outcome missing", err)
	}
	invoke := func(action, id string, expected, replacement []byte) error {
		var output bytes.Buffer
		return configReceiptCommand(path, configTransactionRequest{Action: action, Container: "amnezia-wireguard", Operation: id, Expected: expected, Candidate: replacement}, &output)
	}
	if err := invoke("ack-receipt", id, original, candidate); err == nil {
		t.Fatal("receipt acknowledged while native transaction pending")
	}
	txn, err = resumeConfigTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := txn.finish(false); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path+".amnezia-receipts", first)
	if _, err := os.Lstat(path + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed journal remains")
	}
	if err := invoke("receipt-status", id, original, candidate); err != nil {
		t.Fatal(err)
	}
	if err := invoke("ack-receipt", id, []byte("foreign expected"), candidate); err == nil {
		t.Fatal("wrong receipt context accepted")
	}
	assertConfig(t, path+".amnezia-receipts", first)
	if err := invoke("ack-receipt", id, original, candidate); err != nil {
		t.Fatal(err)
	}
	if err := invoke("ack-receipt", id, original, candidate); err != nil {
		t.Fatal("lost acknowledgment replay failed", err)
	}
	if err := invoke("receipt-status", id, original, candidate); err == nil {
		t.Fatal("acknowledged receipt retained")
	}
}
func TestNativeReceiptCapacityAndForeignStoreRefuseBeforeMutation(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	records := map[string]configReceipt{}
	for i := 0; i < maxConfigReceipts; i++ {
		id := configHash([]byte{byte(i)})
		records[id] = configReceipt{OriginalHash: configHash(original), CandidateHash: configHash(candidate), State: "pending"}
	}
	if err := writeConfigReceipts(path, configReceipts{Version: 1, Records: records}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path + ".amnezia-receipts")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = configReceiptCommand(path, configTransactionRequest{Action: "prepare-receipt", Container: "amnezia-wireguard", Operation: strings.Repeat("c", 64), Expected: original, Candidate: candidate}, &output)
	if err == nil || !strings.Contains(err.Error(), "capacity") || output.Len() != 0 {
		t.Fatal("receipt limit did not fail before native invocation", err)
	}
	assertConfig(t, path, original)
	assertConfig(t, path+".amnezia-receipts", raw)
	for _, bad := range []string{`{"version":99,"records":{}}`, `{"version":1,"records":null}`, `{"version":1,"records":{},"unknown":true}`} {
		if err := os.WriteFile(path+".amnezia-receipts", []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if txn, err := beginConfigTransaction(path, original, candidate); err == nil {
			txn.close()
			t.Fatal("mutation accepted unknown receipt store")
		}
		assertConfig(t, path, original)
	}
	if err := os.WriteFile(path+".amnezia-receipts", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path+".amnezia-receipts", path+".foreign-receipt"); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigReceipts(path); err == nil {
		t.Fatal("linked receipt store accepted")
	}
	assertConfig(t, path+".amnezia-receipts", raw)
}
func TestReceiptRemovedPeerRequiresOneUnambiguousKey(t *testing.T) {
	header := "[Interface]\nPrivateKey = " + testKey('P') + "\n"
	a := "[Peer]\nPublicKey = " + testKey('A') + " # key comment\nAllowedIPs = 10.8.0.2/32\n"
	b := "[Peer]\nPublicKey = " + testKey('B') + "\nAllowedIPs = 10.8.0.3/32\n"
	key, err := receiptRemovedPeer([]byte(header+a+b), []byte(header+b))
	if err != nil || key != testKey('A') {
		t.Fatal("exact revoked key not recognized", err)
	}
	for _, pair := range [][2]string{{header + a + b, header}, {header + a, header + b}, {header + a + a, header}, {header + a, header + a}} {
		if _, err := receiptRemovedPeer([]byte(pair[0]), []byte(pair[1])); err == nil {
			t.Fatal("ambiguous receipt removal accepted")
		}
	}
}

func TestOwnedHelperUpgradePreservesReceiptsAndRejectsUnknownFormat(t *testing.T) {
	path, original, _ := transactionFixture(t)
	target := filepath.Join(filepath.Dir(path), "helper")
	startup := filepath.Join(filepath.Dir(path), "start.sh")
	if err := installOwnedConfigHelper(path, startup, target, []byte("first helper")); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	receipts := configReceipts{Version: 1, Records: map[string]configReceipt{id: {OriginalHash: configHash(original), CandidateHash: configHash([]byte("candidate")), State: "committed", NativeOperation: strings.Repeat("b", 64)}}}
	if err := writeConfigReceipts(path, receipts); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path + ".amnezia-receipts")
	if err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, []byte("second helper")); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path+".amnezia-receipts", saved)
	assertConfig(t, path, original)
	bad := []byte(`{"version":99,"records":{}}`)
	if err := os.WriteFile(path+".amnezia-receipts", bad, 0600); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, []byte("third helper")); err == nil {
		t.Fatal("unknown receipt format upgraded")
	}
	assertConfig(t, target, []byte("second helper"))
	assertConfig(t, path+".amnezia-receipts", bad)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, []byte("third helper")); err == nil {
		t.Fatal("unknown receipts allowed missing-helper restoration")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("helper published despite unknown receipts")
	}
	assertConfig(t, path+".amnezia-receipts", bad)
	if err := os.WriteFile(path+".amnezia-receipts", saved, 0600); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, []byte("third helper")); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path+".amnezia-receipts", saved)
	assertConfig(t, path, original)
}

func TestClientTableMigrationPreservesLegacyDataAndRejectsStaleOrLossyWrites(t *testing.T) {
	for _, legacy := range [][]byte{[]byte(`{"peer":{"clientName":"old","custom":{"n":7,"flag":true},"creationDate":"keep"}}`), {}, []byte(`{}`)} {
		path, _, _ := transactionFixture(t)
		table := filepath.Join(filepath.Dir(path), "clientsTable")
		if err := os.WriteFile(table, legacy, 0640); err != nil {
			t.Fatal(err)
		}
		candidate := []byte(`[{"clientId":"peer","userData":{"creationDate":"keep","custom":{"flag":true,"n":7},"clientName":"old"}}]`)
		invoke := func(action string, expected, replacement []byte) error {
			raw, err := json.Marshal(configTransactionRequest{Action: action, Container: "amnezia-wireguard", Expected: expected, Candidate: replacement})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			return configTransactionCommand(bytes.NewReader(raw), &output, map[string]string{"amnezia-wireguard": path})
		}
		if len(legacy) > 2 {
			for _, lossy := range [][]byte{[]byte(`[]`), []byte(`[{"clientId":"peer","userData":{"clientName":"old"}}]`), []byte(`[{"clientId":"peer","userData":{"creationDate":"changed","custom":{"flag":true,"n":7},"clientName":"old"}}]`)} {
				if err := invoke("migrate-client-table", legacy, lossy); err == nil {
					t.Fatal("legacy metadata loss accepted")
				}
				assertConfig(t, table, legacy)
			}
		}
		if err := invoke("replace-client-table", legacy, candidate); err == nil {
			t.Fatal("ordinary CAS silently migrated legacy metadata")
		}
		if err := invoke("migrate-client-table", legacy, candidate); err != nil {
			t.Fatal(err)
		}
		assertConfig(t, table, candidate)
		if err := invoke("check-client-table", candidate, nil); err != nil {
			t.Fatal("migration reply could not be reconciled", err)
		}
		if err := invoke("migrate-client-table", legacy, candidate); !errors.Is(err, errConfigConflict) {
			t.Fatal("stale migration accepted", err)
		}
		info, err := os.Stat(table)
		if err != nil || info.Mode().Perm() != 0640 {
			t.Fatal("migration changed mode", err)
		}
	}
	for _, invalid := range [][]byte{[]byte(`null`), []byte(`{"peer":null}`), []byte(`{"peer":3}`), []byte(`{"":{}}`), []byte(`broken`)} {
		if validLegacyClientTable(invalid) {
			t.Fatal("malformed legacy table accepted")
		}
	}
}

func TestLegacyMigrationComparesNumbersWithoutRounding(t *testing.T) {
	for _, pair := range [][2]string{{"1e3", "1000"}, {"1.0", "1"}, {"-0.00e100", "0"}, {"123.4500", "12345e-2"}, {"1e9223372036854775807", "10e9223372036854775806"}} {
		if !equalMetadataJSON(json.Number(pair[0]), json.Number(pair[1])) {
			t.Fatal("equivalent numeric value rejected", pair)
		}
	}
	for _, pair := range [][2]string{{"9007199254740993", "9007199254740992"}, {"1.0000000000000001", "1"}, {"1e3", "1001"}, {"1e9223372036854775807", "1e-9223372036854775808"}} {
		if equalMetadataJSON(json.Number(pair[0]), json.Number(pair[1])) {
			t.Fatal("numeric data loss accepted", pair)
		}
	}
	old := []byte(`{"peer":{"clientName":"old","custom":{"n":1e3,"large":9007199254740993}}}`)
	good := []byte(`[{"clientId":"peer","userData":{"custom":{"large":9007199254740993,"n":1000},"clientName":"old"}}]`)
	bad := bytes.Replace(good, []byte("9007199254740993"), []byte("9007199254740992"), 1)
	if !clientTableMigrationPreserves(old, good) || clientTableMigrationPreserves(old, bad) {
		t.Fatal("nested numeric migration guard is not exact")
	}
}

func TestPeerMetadataIntentGuardsOnlyReservedEntry(t *testing.T) {
	path, _, _ := transactionFixture(t)
	key := testKey('B')
	id := strings.Repeat("a", 64)
	initial := []byte(`[{"clientId":"` + key + `","userData":{"name":"reserved","n":1e3}},{"clientId":"other","userData":{"name":"old"}}]`)
	entry, err := decodeMetadataJSON([]byte(`{"clientId":"` + key + `","userData":{"n":1000,"name":"reserved"}}`))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := metadataDigest(entry)
	if err != nil {
		t.Fatal(err)
	}
	receipts := configReceipts{Version: 1, Records: map[string]configReceipt{id: {OriginalHash: strings.Repeat("b", 64), CandidateHash: strings.Repeat("c", 64), State: "pending", TargetKey: key, TargetMetadataHash: digest, TargetPeerHash: strings.Repeat("d", 64)}}}
	if err := writeConfigReceipts(path, receipts); err != nil {
		t.Fatal(err)
	}
	loaded, err := readConfigReceipts(path)
	if err != nil || loaded.Version != 2 || loaded.Records[id].TargetKey != key {
		t.Fatal("peer identity not durably recorded", err)
	}
	unchanged := bytes.Replace(initial, []byte(`"name":"old"`), []byte(`"name":"new"`), 1)
	if err := guardPeerMetadata(path, configTransactionRequest{Action: "replace-client-table", Candidate: unchanged}, loaded, initial); err != nil {
		t.Fatal("unrelated metadata blocked", err)
	}
	changed := bytes.Replace(initial, []byte(`"name":"reserved"`), []byte(`"name":"foreign"`), 1)
	for _, operation := range []string{"", strings.Repeat("f", 64), id} {
		if err := guardPeerMetadata(path, configTransactionRequest{Action: "replace-client-table", Operation: operation, Candidate: changed}, loaded, initial); err == nil {
			t.Fatal("reserved metadata renamed")
		}
	}
	removed := []byte(`[{"clientId":"other","userData":{"name":"old"}}]`)
	if err := guardPeerMetadata(path, configTransactionRequest{Action: "replace-client-table", Operation: id, Candidate: removed}, loaded, initial); err == nil {
		t.Fatal("pending intent deleted metadata")
	}
	committed := loaded.Records[id]
	committed.State = "committed"
	committed.NativeOperation = strings.Repeat("e", 64)
	loaded.Records[id] = committed
	if err := guardPeerMetadata(path, configTransactionRequest{Action: "replace-client-table", Operation: id, Candidate: removed}, loaded, changed); !errors.Is(err, errConfigConflict) {
		t.Fatal("foreign target edit not protected", err)
	}
	if err := guardPeerMetadata(path, configTransactionRequest{Action: "replace-client-table", Candidate: initial}, loaded, removed); err == nil {
		t.Fatal("reserved metadata resurrected")
	}
	// Older formats must never silently contain the new intent fields.
	raw, err := json.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":1`), 1)
	if err := os.WriteFile(path+".amnezia-receipts", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigReceipts(path); err == nil {
		t.Fatal("new intent accepted in old format")
	}
}
func TestExpectedMetadataEntryIsNotAcceptedByUnrelatedActions(t *testing.T) {
	path, _, _ := transactionFixture(t)
	raw, _ := json.Marshal(configTransactionRequest{Action: "capabilities", Container: "amnezia-wireguard", ExpectedEntry: json.RawMessage(`{}`)})
	var output bytes.Buffer
	if err := configTransactionCommand(bytes.NewReader(raw), &output, map[string]string{"amnezia-wireguard": path}); err == nil || output.Len() != 0 {
		t.Fatal("unexpected entry accepted")
	}
}

func TestOwnedHelperRestorePreservesPeerMetadataIntent(t *testing.T) {
	path, original, candidate := transactionFixture(t)
	target := filepath.Join(filepath.Dir(path), "helper")
	startup := filepath.Join(filepath.Dir(path), "start.sh")
	if err := installOwnedConfigHelper(path, startup, target, []byte("first helper")); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	record := configReceipt{OriginalHash: configHash(original), CandidateHash: configHash(candidate), State: "pending", TargetKey: testKey('B'), TargetMetadataHash: strings.Repeat("b", 64), TargetPeerHash: strings.Repeat("c", 64)}
	if err := writeConfigReceipts(path, configReceipts{Version: 2, Records: map[string]configReceipt{id: record}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path + ".amnezia-receipts")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, []byte("second helper")); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, target, []byte("second helper"))
	assertConfig(t, path, original)
	assertConfig(t, path+".amnezia-receipts", raw)
}

func TestReceiptQuickHooksDoNotChangePeerIdentity(t *testing.T) {
	header := "[Interface]\nPrivateKey = " + testKey('P') + "\n"
	hooks := "Address = 10.8.0.1/24\nDNS = 10.8.0.1\nMTU = 1280\nPostUp = echo first\nPostUp = echo second # preserved in file\nPreDown = echo third\nPreDown = echo fourth\n"
	a := "[Peer]\nPublicKey = " + testKey('A') + "\nAllowedIPs = 10.8.0.2/32\n"
	b := "[Peer]\nPublicKey = " + testKey('B') + "\nAllowedIPs = 10.8.0.3/32\n"
	original := []byte(header + hooks + a + b)
	copyOriginal := append([]byte(nil), original...)
	key, err := receiptRemovedPeer(original, []byte(header+hooks+b))
	if err != nil || key != testKey('A') {
		t.Fatal("valid repeated quick hooks prevented revocation", err)
	}
	native, err := receiptNativeConfig(original)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := canonicalNativeConfig(native)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := canonicalNativeConfig([]byte(header + a + b))
	if err != nil || actual != expected || !bytes.Equal(original, copyOriginal) {
		t.Fatal("quick projection changed native identity or source bytes", err)
	}
	for _, invalid := range []string{
		header + "PrivateKey = " + testKey('P') + "\n" + a,
		header + a + "PublicKey = " + testKey('B') + "\n",
		header + "[Peer]\nAllowedIPs = 10.8.0.2/32\n",
		"MTU = 1280\n" + header + a,
		header + "[Unknown]\nPostUp = echo ignored\n" + a,
	} {
		if _, err := receiptNativeConfig([]byte(invalid)); err == nil {
			t.Fatal("malformed configuration accepted")
		}
	}
}

func TestScopedPeerRemovalPreservesIndependentBytes(t *testing.T) {
	header := "# keep header\r\n[Interface]\r\nPrivateKey = " + testKey('P') + "\r\nPostUp = echo first\r\nPostUp = echo second\r\n"
	a := "[Peer] # remove owned block\r\nPublicKey = " + testKey('A') + " # identity\r\nAllowedIPs = 10.8.0.2/32\r\n# owned trailing comment\r\n"
	b := "[Peer]\r\n# untouched bytes\r\nPublicKey = " + testKey('B') + "\r\nPersistentKeepalive = 17\r\n"
	for _, parts := range [][2]string{{a, b}, {b, a}} {
		original := []byte(header + parts[0] + parts[1])
		candidate, err := removeReceiptPeer(original, testKey('A'))
		if err != nil || !bytes.Equal(candidate, []byte(header+b)) {
			t.Fatal("independent bytes changed", err)
		}
	}
	for _, raw := range []string{header + b, header + a + a, header + "[Peer]\nAllowedIPs = 10.8.0.2/32\n"} {
		if _, err := removeReceiptPeer([]byte(raw), testKey('A')); err == nil {
			t.Fatal("ambiguous or missing target accepted")
		}
	}
}

func TestScopedNativeIntentAllowsOnlyOwnedRemoval(t *testing.T) {
	header := "[Interface]\nPrivateKey = " + testKey('P') + "\n"
	a := "[Peer]\nPublicKey = " + testKey('A') + "\nAllowedIPs = 10.8.0.2/32\n"
	b := "[Peer]\nPublicKey = " + testKey('B') + "\nAllowedIPs = 10.8.0.3/32\n"
	original := []byte(header + a + b)
	unrelated := []byte(header + a + b + "PersistentKeepalive = 17\n")
	removed := []byte(header + b + "PersistentKeepalive = 17\n")
	id := strings.Repeat("a", 64)
	fingerprint, err := receiptPeerFingerprint(original, testKey('A'))
	if err != nil {
		t.Fatal(err)
	}
	record := configReceipt{TargetKey: testKey('A'), TargetPeerHash: fingerprint, State: "pending"}
	receipts := configReceipts{Records: map[string]configReceipt{id: record}}
	if err := guardNativePeerIntents(receipts, "", original, unrelated); err != nil {
		t.Fatal("unrelated change blocked", err)
	}
	if err := guardNativePeerIntents(receipts, id, unrelated, removed); err != nil {
		t.Fatal("rebased owned removal blocked", err)
	}
	for _, attempt := range []struct {
		owner         string
		before, after []byte
	}{
		{"", unrelated, removed}, {strings.Repeat("b", 64), unrelated, removed},
		{id, unrelated, []byte(header + b)}, {"", original, []byte(strings.Replace(string(original), "10.8.0.2/32", "10.8.0.9/32", 1))},
	} {
		if err := guardNativePeerIntents(receipts, attempt.owner, attempt.before, attempt.after); err == nil {
			t.Fatal("foreign change accepted")
		}
	}
	journal := configJournal{Version: 7, ReceiptOperation: id, Operation: strings.Repeat("c", 64), Original: unrelated, CandidateHash: configHash(removed), NativeOriginal: original, NativeHash: configHash(original)}
	if !configNativeJournalOK(journal) || validatePeerJournal(journal, receipts) != nil {
		t.Fatal("bound rebased journal refused")
	}
	journal.CandidateHash = configHash([]byte(header + b))
	if validatePeerJournal(journal, receipts) == nil {
		t.Fatal("journal discards later peer change")
	}
	journal.Version = 6
	if configNativeJournalOK(journal) {
		t.Fatal("binding accepted in old format")
	}
	record.State, record.NativeOperation = "committed", strings.Repeat("c", 64)
	receipts.Records[id] = record
	if err := guardNativePeerIntents(receipts, "", removed, []byte(header+b+"PersistentKeepalive = 23\n")); err != nil {
		t.Fatal("later independent edit blocked", err)
	}
	if err := guardNativePeerIntents(receipts, "", removed, unrelated); err == nil {
		t.Fatal("committed target resurrected")
	}
}

func TestOwnedHelperRestorePreservesScopedNativeJournal(t *testing.T) {
	path, _, _ := transactionFixture(t)
	header := "[Interface]\nPrivateKey = " + testKey('P') + "\n"
	a := "[Peer]\nPublicKey = " + testKey('A') + "\nAllowedIPs = 10.8.0.2/32\n"
	b := "[Peer]\nPublicKey = " + testKey('B') + "\nAllowedIPs = 10.8.0.3/32\nPersistentKeepalive = 17\n"
	original, candidate := []byte(header+a+b), []byte(header+b)
	if err := os.WriteFile(path, original, 0640); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(path), "helper")
	startup := filepath.Join(filepath.Dir(path), "start.sh")
	if err := installOwnedConfigHelper(path, startup, target, []byte("first helper")); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	fingerprint, err := receiptPeerFingerprint(original, testKey('A'))
	if err != nil {
		t.Fatal(err)
	}
	receipts := configReceipts{Version: 2, Records: map[string]configReceipt{id: {State: "pending", OriginalHash: configHash(original), CandidateHash: configHash(candidate), TargetKey: testKey('A'), TargetMetadataHash: strings.Repeat("b", 64), TargetPeerHash: fingerprint}}}
	if err := writeConfigReceipts(path, receipts); err != nil {
		t.Fatal(err)
	}
	lock, err := lockConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := beginLockedConfigTransaction(path, original, candidate, func(journal *configJournal) error {
		journal.ReceiptOperation = id
		journal.NativeOriginal, journal.NativeHash = original, configHash(original)
		return nil
	}, lock)
	if err != nil {
		t.Fatal(err)
	}
	transaction.close()
	journalBefore, err := os.ReadFile(path + ".amnezia-journal")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := installOwnedConfigHelper(path, startup, target, []byte("replacement helper")); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path+".amnezia-journal", journalBefore)
	assertConfig(t, path, candidate)
	resumed, err := resumeConfigTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.close()
	if resumed.journal.Version != 7 || resumed.journal.ReceiptOperation != id {
		t.Fatal("scoped binding lost")
	}
	if err := resumed.saveJournal(); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path+".amnezia-journal", journalBefore)
}
