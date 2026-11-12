package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Checked against the packaged shared startup resource by ordinary tests.
const forwardingPrefixSize = 2554
const forwardingPrefixHash = "411736a20ba6cdada055e7364efea14cbd88ee15158568a9beaebcc708800758"

func verifiedForwardingProgram(path string) ([]byte, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || parent != filepath.Dir(path) {
		return nil, errors.New("unsafe startup directory")
	}
	info, err := os.Stat(parent)
	if err != nil || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("unsafe startup directory")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		return nil, errors.New("foreign startup directory")
	}
	raw, info, err := readConfigFile(path, 4<<20)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("unsafe startup script")
	}
	if len(raw) < forwardingPrefixSize || configHash(raw[:forwardingPrefixSize]) != forwardingPrefixHash {
		return nil, errors.New("installed startup lacks verified live IPv6 preparation")
	}
	// Execute the verified snapshot ONLY, never the installed teardown/startup body.
	return bytes.Clone(raw[:forwardingPrefixSize]), nil
}

func liveForwardingCommand(ctx context.Context, program []byte, iface string) *exec.Cmd {
	command := protocolCommand(ctx, "/bin/bash", "-s", "--", "--amnezia-prepare-ipv6-forwarding", iface)
	// Noninteractive bash otherwise sources BASH_ENV before reading our program.
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.Stdin = bytes.NewReader(program)
	return command
}

func prepareConfigForwarding(transaction *configTransaction, container string) error {
	if transaction.lock == nil || transaction.journal.IPv6 == nil || !transaction.journal.NativeApplied {
		return errors.New("IPv6 migration is not applied")
	}
	current, info, err := readConfigFile(transaction.path, 4<<20)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != transaction.journal.UID || int(stat.Gid) != transaction.journal.GID || uint32(info.Mode().Perm()) != transaction.journal.Mode || configHash(current) != transaction.journal.CandidateHash {
		return errConfigConflict
	}
	if err := verifyIPv6Commit(transaction, container); err != nil {
		return err
	}
	native, err := captureNativeProtocol(container)
	if err != nil {
		return err
	}
	if err := verifyNativeConfigBaseline(container, transaction.path, native); err != nil {
		return err
	}
	program, err := verifiedForwardingProgram("/opt/amnezia/start.sh")
	if err != nil {
		return err
	}
	iface, err := protocolInterface(container)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := liveForwardingCommand(ctx, program, iface)
	if err := command.Run(); err != nil {
		return errors.New("cannot prepare live IPv6 forwarding")
	}
	return nil
}
