package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProtocolWriterCannotOutliveTransactionOwner(t *testing.T) {
	if marker := os.Getenv("AMNEZIA_PROTOCOL_OWNER_TEST"); marker != "" {
		command := protocolCommand(context.Background(), "/bin/sh", "-c", `printf ready > "$AMNEZIA_PROTOCOL_OWNER_TEST.started"; sleep 1; printf forbidden > "$AMNEZIA_PROTOCOL_OWNER_TEST.late"`)
		if err := command.Start(); err != nil {
			os.Exit(32)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(marker + ".started"); err == nil {
				os.Exit(23)
			}
			time.Sleep(5 * time.Millisecond)
		}
		command.Process.Kill()
		os.Exit(33)
	}
	marker := filepath.Join(t.TempDir(), "writer")
	owner := exec.Command(os.Args[0], "-test.run=^TestProtocolWriterCannotOutliveTransactionOwner$")
	owner.Env = append(os.Environ(), "AMNEZIA_PROTOCOL_OWNER_TEST="+marker)
	err := owner.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatal("owner did not exit after child started", err)
	}
	if _, err := os.Stat(marker + ".started"); err != nil {
		t.Fatal("protocol writer never started", err)
	}
	// Without the parent-death guard the child writes after one second.
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker + ".late"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("writer survived the owner and modified state", err)
	}
}

func TestNativeBaselineCanonicalizesRoutesDefaultsAndRoaming(t *testing.T) {
	base := "[Interface]\nPrivateKey = " + testKey('P') + "\nListenPort = 51820\nFwMark = 0xca6c\n[Peer]\nPublicKey = " + testKey('A') + "\nAllowedIPs = fd77::2/128, 10.77.0.2/32\n"
	alternate := strings.Replace(base, "FwMark = 0xca6c", "FwMark = 51820\nS3 = 0", 1)
	alternate = strings.Replace(alternate, "fd77::2/128, 10.77.0.2/32", "10.77.0.2/32, fd77::2/128 # original note", 1) + "Endpoint = 127.0.0.1:29999\n"
	before, err := canonicalNativeConfig([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	after, err := canonicalNativeConfig([]byte(alternate))
	if err != nil || before != after {
		t.Fatal("equivalent native settings mismatch", err)
	}
	changed := strings.Replace(base, "10.77.0.2/32", "10.77.0.3/32", 1)
	different, err := canonicalNativeConfig([]byte(changed))
	if err != nil || different == before {
		t.Fatal("route mismatch hidden", err)
	}
	changed = strings.Replace(base, testKey('P'), testKey('Q'), 1)
	different, err = canonicalNativeConfig([]byte(changed))
	if err != nil || different == before {
		t.Fatal("server identity mismatch hidden", err)
	}
}
