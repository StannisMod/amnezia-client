package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// The production helper runs in Linux VPN containers. Do not let a killed SSH
// helper leave a protocol-writing child alive after releasing the sidecar lock.
func protocolCommand(ctx context.Context, binary string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, binary, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = time.Second
	return command
}

func syncNativeProtocol(container, path string) error {
	binary, iface := "", ""
	switch container {
	case "amnezia-wireguard":
		binary, iface = "wg", "wg0"
	case "amnezia-awg2":
		binary, iface = "awg", "awg0"
	default:
		return errors.New("unsupported protocol container")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Arguments are fixed by the container allowlist. No shell or profile hooks.
	stripped, err := protocolCommand(ctx, binary+"-quick", "strip", path).Output()
	if err != nil || len(stripped) > 8<<20 {
		return errors.New("cannot prepare protocol configuration")
	}
	command := protocolCommand(ctx, binary, "syncconf", iface, "/dev/stdin")
	command.Stdin = bytes.NewReader(stripped)
	// Protocol diagnostics may contain key material: never return them to a caller.
	if err := command.Run(); err != nil {
		return errors.New("cannot apply protocol configuration")
	}
	return nil
}

func applyConfigTransactionRuntime(transaction *configTransaction, container string, rollback bool) error {
	if transaction.lock == nil {
		return errors.New("closed configuration transaction")
	}
	current, info, err := readConfigFile(transaction.path, 4<<20)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != transaction.journal.UID || int(stat.Gid) != transaction.journal.GID || uint32(info.Mode().Perm()) != transaction.journal.Mode {
		return errConfigConflict
	}
	hash := configHash(current)
	if hash != transaction.journal.CandidateHash && !(rollback && hash == transaction.journal.OriginalHash) {
		return errConfigConflict
	}
	if rollback && hash != transaction.journal.OriginalHash {
		if err := writeConfigAtomic(transaction.path, transaction.journal.Original, os.FileMode(transaction.journal.Mode), transaction.journal.UID, transaction.journal.GID, false); err != nil {
			return err
		}
	}
	// Keep the lock AND durable journal until native synchronization succeeds.
	// On any failure a later rollback-live retries the original configuration.
	if err := syncNativeProtocol(container, transaction.path); err != nil {
		return err
	}
	if rollback {
		return transaction.finish(true)
	}
	return nil
}
