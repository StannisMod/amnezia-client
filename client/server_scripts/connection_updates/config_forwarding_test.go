package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
