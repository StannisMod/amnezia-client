package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestForwardingProgramMatchesPackagedResource(t *testing.T) {
	resource, err := os.ReadFile("../enable_ipv6_forwarding.sh")
	if err != nil {
		t.Fatal(err)
	}
	prefix := append([]byte("#!/bin/bash\n"), resource...)
	prefix = append(prefix, '\n')
	if len(prefix) != forwardingPrefixSize || configHash(prefix) != forwardingPrefixHash {
		t.Fatal("forwarding verifier does not match packaged startup resource")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "start.sh")
	marker := filepath.Join(dir, "forbidden-startup-body")
	raw := append(bytes.Clone(prefix), []byte("touch '"+marker+"'\nexit 88\n")...)
	if err := os.WriteFile(path, raw, 0700); err != nil {
		t.Fatal(err)
	}
	verified, err := verifiedForwardingProgram(path)
	if err != nil || !bytes.Equal(verified, prefix) {
		t.Fatal("valid program rejected", err)
	}
	// Missing interface must exit 64 in the verified dispatch without executing
	// ANY original startup body or requiring privileged network changes.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	command := protocolCommand(ctx, "/bin/bash", "-s", "--", "--amnezia-prepare-ipv6-forwarding")
	command.Stdin = bytes.NewReader(verified)
	if err := command.Run(); err == nil || command.ProcessState.ExitCode() != 64 {
		t.Fatal("verified dispatch did not reject missing argument", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("startup body executed")
	}
	environmentHook := filepath.Join(dir, "bash-env")
	if err := os.WriteFile(environmentHook, []byte("touch '"+marker+"'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASH_ENV", environmentHook)
	isolated := liveForwardingCommand(ctx, verified, "invalid")
	if err := isolated.Run(); err == nil || isolated.ProcessState.ExitCode() != 1 {
		t.Fatal("invalid interface accepted", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("inherited shell hook executed")
	}
	for _, bad := range [][]byte{[]byte("#!/bin/bash\ntouch forbidden\n"), append([]byte("#!/bin/sh\n"), prefix...), append(bytes.Clone(prefix[:len(prefix)-1]), 'x')} {
		if err := os.WriteFile(path, bad, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := verifiedForwardingProgram(path); err == nil {
			t.Fatal("unrecognized startup accepted")
		}
	}
	if err := os.WriteFile(path, raw, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedForwardingProgram(path); err == nil {
		t.Fatal("writable startup accepted")
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.sh")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedForwardingProgram(path); err == nil {
		t.Fatal("hardlinked startup accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedForwardingProgram(link); err == nil {
		t.Fatal("symlink startup accepted")
	}
}

func TestStartupMigrationUsesDurableTransactionWithoutChangingBody(t *testing.T) {
	resource, err := os.ReadFile("../enable_ipv6_forwarding.sh")
	if err != nil {
		t.Fatal(err)
	}
	prefix := append([]byte("#!/bin/bash\n"), resource...)
	prefix = append(prefix, '\n')
	original := []byte("#!/bin/bash\n# existing startup must remain intact\nexit 23\n")
	candidate := append(bytes.Clone(prefix), original[len("#!/bin/bash\n"):]...)
	path := filepath.Join(t.TempDir(), "start.sh")
	if err := os.WriteFile(path, original, 0700); err != nil {
		t.Fatal(err)
	}
	invoke := func(action, operation string, expected, replacement []byte) (map[string]any, error) {
		raw, _ := json.Marshal(configTransactionRequest{Action: action, Container: "amnezia-wireguard", Operation: operation, Expected: expected, Candidate: replacement})
		var output bytes.Buffer
		err := startupTransactionCommand(bytes.NewReader(raw), &output, map[string]string{"amnezia-wireguard": path})
		var result map[string]any
		if err == nil {
			err = json.Unmarshal(output.Bytes(), &result)
		}
		return result, err
	}
	for _, bad := range [][]byte{append(bytes.Clone(candidate), []byte("changed body\n")...), original, append(bytes.Clone(prefix), []byte("exit 0\n")...)} {
		if _, err := invoke("stage", "", original, bad); err == nil {
			t.Fatal("unsafe startup replacement accepted")
		}
		assertConfig(t, path, original)
	}
	if startupCandidateOK([]byte("#!/bin/sh\nexit 23\n"), candidate) {
		t.Fatal("startup interpreter silently changed")
	}
	if startupCandidateOK([]byte("#!/bin/bash -e\nexit 23\n"), candidate) {
		t.Fatal("interpreter options silently changed")
	}
	staged, err := invoke("stage", "", original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	operation := staged["operation"].(string)
	status, err := invoke("status", "", nil, nil)
	if err != nil || status["operation"] != operation {
		t.Fatal("lost stage result not recoverable", err)
	}
	for _, action := range []string{"apply", "rollback-live", "prepare-forwarding", "stage-ipv6"} {
		if _, err := invoke(action, operation, nil, nil); err == nil {
			t.Fatal("startup transaction allowed protocol operation")
		}
	}
	if _, err := invoke("rollback", strings.Repeat("0", 64), nil, nil); err == nil {
		t.Fatal("foreign operation accepted")
	}
	if _, err := invoke("rollback", operation, nil, nil); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path, original)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("startup mode changed", err)
	}
	staged, err = invoke("stage", "", original, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invoke("commit", staged["operation"].(string), nil, nil); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, path, candidate)
	if !startupCandidateOK(candidate, candidate) || startupCandidateOK(candidate, append(bytes.Clone(prefix), candidate[len("#!/bin/bash\n"):]...)) {
		t.Fatal("repeat migration duplicated prefix")
	}
	// A later writer must survive recovery rather than be overwritten.
	staged, err = invoke("stage", "", candidate, candidate)
	if err != nil {
		t.Fatal(err)
	}
	independent := append(bytes.Clone(candidate), []byte("# independent edit\n")...)
	if err := os.WriteFile(path, independent, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke("rollback", staged["operation"].(string), nil, nil); err == nil {
		t.Fatal("independent startup edit overwritten")
	}
	assertConfig(t, path, independent)
}
