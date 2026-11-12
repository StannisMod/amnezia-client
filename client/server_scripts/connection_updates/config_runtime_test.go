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

func TestLiveMutationPreservesQuickOnlySettings(t *testing.T) {
	original := "[Interface]\nPrivateKey = old\nAddress = 10.77.0.1/24\nMTU = 1280\nDNS = 10.77.0.1\nTable = auto\nPreUp = echo pre\nPostUp = echo first\nPostUp = echo second\nPreDown = echo before\nPostDown = echo after\nSaveConfig = false\n[Peer]\nPublicKey = peer\nAllowedIPs = 10.77.0.2/32\n"
	nativeOnly := strings.Replace(strings.Replace(original, "PrivateKey = old", "PrivateKey = new", 1), "10.77.0.2/32", "10.77.0.3/32", 1)
	if !sameQuickSettings([]byte(original), []byte(nativeOnly)) {
		t.Fatal("native mutation rejected")
	}
	for _, key := range []string{"Address", "MTU", "DNS", "Table", "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig"} {
		changed := strings.Replace(original, key+" = ", key+" = changed ", 1)
		if sameQuickSettings([]byte(original), []byte(changed)) {
			t.Fatal("unapplied quick setting accepted", key)
		}
	}
	if sameQuickSettings([]byte(original), []byte(original+"[Interface]\n")) {
		t.Fatal("duplicate interface accepted")
	}
	if err := verifyProtocolCommit(&configTransaction{}, "amnezia-wireguard"); err == nil {
		t.Fatal("closed transaction accepted")
	}
}

func TestInterruptedNativeClassification(t *testing.T) {
	original := []byte("[Interface]\nPrivateKey = " + testKey('P') + "\n[Peer]\nPublicKey = " + testKey('A') + "\nAllowedIPs = 10.8.0.2/32\n")
	candidate := []byte(strings.Replace(string(original), "10.8.0.2/32", "10.8.0.3/32", 1))
	applied, err := classifyInterruptedNative(original, candidate, original)
	if err != nil || applied {
		t.Fatal("original native state not retryable")
	}
	roaming := append(append([]byte{}, candidate...), []byte("Endpoint = 127.0.0.1:19999\n")...)
	applied, err = classifyInterruptedNative(original, candidate, roaming)
	if err != nil || !applied {
		t.Fatal("completed native state not recognized")
	}
	foreign := []byte(strings.Replace(string(original), "10.8.0.2/32", "10.8.0.4/32", 1))
	if _, err := classifyInterruptedNative(original, candidate, foreign); !errors.Is(err, errConfigConflict) {
		t.Fatal("foreign native state accepted")
	}
	partial := append(append([]byte{}, candidate...), []byte("PersistentKeepalive = 25\n")...)
	if _, err := classifyInterruptedNative(original, candidate, partial); !errors.Is(err, errConfigConflict) {
		t.Fatal("partial native state accepted")
	}
	multiCandidate := append(append([]byte{}, candidate...), []byte("PersistentKeepalive = 25\n")...)
	if _, err := classifyInterruptedNative(original, multiCandidate, candidate); !errors.Is(err, errConfigConflict) {
		t.Fatal("partially applied owned changes accepted")
	}
	if _, err := classifyInterruptedNative(original, candidate, []byte("invalid")); err == nil {
		t.Fatal("invalid native state accepted")
	}
}
