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
