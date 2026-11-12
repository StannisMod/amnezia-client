package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
