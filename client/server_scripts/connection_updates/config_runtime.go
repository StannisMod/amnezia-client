package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
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

func nativeProtocolNames(container string) (string, string, error) {
	switch container {
	case "amnezia-wireguard":
		return "wg", "wg0", nil
	case "amnezia-awg2":
		return "awg", "awg0", nil
	default:
		return "", "", errors.New("unsupported protocol container")
	}
}
func stripNativeProtocol(container, path string) ([]byte, error) {
	binary, _, err := nativeProtocolNames(container)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stripped, err := protocolCommand(ctx, binary+"-quick", "strip", path).Output()
	if err != nil || len(stripped) > 4<<20 {
		return nil, errors.New("cannot prepare protocol configuration")
	}
	return stripped, nil
}
func syncNativeProtocolBytes(container string, configuration []byte) error {
	binary, iface, err := nativeProtocolNames(container)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := protocolCommand(ctx, binary, "syncconf", iface, "/dev/stdin")
	command.Stdin = bytes.NewReader(configuration)
	// Protocol diagnostics may contain key material: never return them to a caller.
	if err := command.Run(); err != nil {
		return errors.New("cannot apply protocol configuration")
	}
	return nil
}
func syncNativeProtocol(container, path string) error {
	stripped, err := stripNativeProtocol(container, path)
	if err != nil {
		return err
	}
	return syncNativeProtocolBytes(container, stripped)
}
func captureNativeProtocol(container string) ([]byte, error) {
	binary, iface, err := nativeProtocolNames(container)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := protocolCommand(ctx, binary, "showconf", iface).Output()
	if err != nil || len(raw) == 0 || len(raw) > 4<<20 {
		return nil, errors.New("cannot snapshot native configuration")
	}
	lines := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		// Endpoint is learned dynamically by authenticated roaming. Never pin a
		// previous outer network address when restoring stable peer configuration.
		if strings.TrimSpace(strings.SplitN(line, "=", 2)[0]) != "Endpoint" {
			lines = append(lines, line)
		}
	}
	result := []byte(strings.Join(lines, "\n"))
	if _, _, err := iniInterface(result); err != nil {
		return nil, errors.New("invalid native configuration snapshot")
	}
	return result, nil
}
func canonicalNativeConfig(raw []byte) (string, error) {
	lines := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		field := strings.SplitN(line, "=", 2)
		if len(field) == 2 {
			key, value := strings.TrimSpace(field[0]), strings.TrimSpace(field[1])
			if key == "AllowedIPs" {
				routes := []string{}
				for _, route := range strings.Split(value, ",") {
					prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
					if err != nil {
						return "", errors.New("invalid native route")
					}
					routes = append(routes, prefix.Masked().String())
				}
				sort.Strings(routes)
				value = strings.Join(routes, ",")
			}
			if key == "FwMark" {
				mark, err := strconv.ParseUint(value, 0, 32)
				if err != nil {
					return "", errors.New("invalid native fwmark")
				}
				value = strconv.FormatUint(mark, 10)
			}
			line = key + " = " + value
		}
		lines = append(lines, line)
	}
	return canonicalConfig([]byte(strings.Join(lines, "\n")))
}
func verifyNativeConfigBaseline(container, path string, native []byte) error {
	stripped, err := stripNativeProtocol(container, path)
	if err != nil {
		return err
	}
	expected, err := canonicalNativeConfig(stripped)
	if err != nil {
		return err
	}
	actual, err := canonicalNativeConfig(native)
	if err != nil {
		return err
	}
	if expected != actual {
		return errConfigConflict
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
	if !rollback && len(transaction.journal.NativeOriginal) == 0 {
		native, err := captureNativeProtocol(container)
		if err != nil {
			return err
		}
		transaction.journal.NativeOriginal = native
		transaction.journal.NativeHash = configHash(native)
		if err := transaction.saveJournal(); err != nil {
			return err
		}
	}
	if !rollback {
		// A staged IPv6 migration spans separate helper invocations. Refuse a
		// changed runtime before touching addresses or protocol configuration.
		if transaction.journal.IPv6 != nil && !transaction.journal.NativeWriteIntent {
			native, err := captureNativeProtocol(container)
			if err != nil {
				return err
			}
			expected, err := canonicalNativeConfig(transaction.journal.NativeOriginal)
			if err != nil {
				return err
			}
			actual, err := canonicalNativeConfig(native)
			if err != nil {
				return err
			}
			if actual != expected {
				return errConfigConflict
			}
		}
		if err := applyProtocolIPv6(transaction, container); err != nil {
			return err
		}
	}
	if !rollback && !transaction.journal.NativeWriteIntent {
		transaction.journal.NativeWriteIntent = true
		if err := transaction.saveJournal(); err != nil {
			return err
		}
	}
	// Keep the lock AND durable journal until native synchronization succeeds.
	// On any failure a later rollback-live retries the original configuration.
	if rollback {
		if transaction.journal.NativeWriteIntent {
			if err := syncNativeProtocolBytes(container, transaction.journal.NativeOriginal); err != nil {
				return err
			}
		}
	} else if err := syncNativeProtocol(container, transaction.path); err != nil {
		return err
	}
	if rollback {
		transaction.journal.NativeWriteIntent = false
		transaction.journal.NativeApplied = false
		if transaction.journal.IPv6 != nil {
			transaction.journal.IPv6.Applied = false
		}
		if len(transaction.journal.NativeOriginal) != 0 {
			if err := transaction.saveJournal(); err != nil {
				return err
			}
		}
		if err := rollbackProtocolIPv6(transaction, container); err != nil {
			return err
		}
		return transaction.finish(true)
	}
	transaction.journal.NativeApplied = true
	if transaction.journal.IPv6 != nil {
		transaction.journal.IPv6.Applied = true
	}
	if err := transaction.saveJournal(); err != nil {
		return err
	}
	return nil
}
