package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Checked against the packaged shared startup resource by ordinary tests.
const forwardingPrefixSize = 3000
const forwardingPrefixHash = "fb801ab78f2591aedd20107d5194862aa9faaed997a971f2240022d9ec0b0666"

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
	if transaction.lock == nil || transaction.journal.IPv6 == nil || !transaction.journal.NativeApplied || transaction.journal.NativeRollbackHash != "" {
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

// Startup migration changes only a verified prefix. The existing script body
// remains byte-for-byte intact, and the normal file transaction retains backup.
func startupCandidateOK(original, candidate []byte) bool {
	if len(candidate) < forwardingPrefixSize || configHash(candidate[:forwardingPrefixSize]) != forwardingPrefixHash {
		return false
	}
	body, ok := startupBody(original)
	return ok && bytes.Equal(candidate[forwardingPrefixSize:], body)
}

func startupTransactionCommand(input io.Reader, output io.Writer, paths map[string]string) error {
	raw, err := io.ReadAll(io.LimitReader(input, (12<<20)+1))
	if err != nil || len(raw) > 12<<20 {
		return errors.New("invalid startup transaction request")
	}
	var request configTransactionRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.ServerIPv6 != "" {
		return errors.New("invalid startup transaction request")
	}
	if request.Action == "check-current" {
		path, exists := paths[request.Container]
		if !exists || request.Operation != "" || len(request.Expected) == 0 || len(request.Expected) > 4<<20 || len(request.Candidate) != 0 || len(request.ExpectedEntry) != 0 {
			return errors.New("invalid startup state check")
		}
		lock, err := lockConfig(path)
		if err != nil {
			return err
		}
		defer lock.Close()
		if _, err := os.Lstat(path + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("startup transaction is pending")
		}
		current, info, err := readConfigFile(path, 4<<20)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Nlink != 1 || int(owner.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 || !bytes.Equal(current, request.Expected) {
			return errConfigConflict
		}
		return json.NewEncoder(output).Encode(map[string]any{"version": 1, "current": true, "candidateHash": configHash(current)})
	}
	switch request.Action {
	case "stage":
		if !startupCandidateOK(request.Expected, request.Candidate) && !startupBootCandidateOK(request.Expected, request.Candidate, request.Container) {
			return errors.New("startup migration requires a verified prefix and recognized body transformation")
		}
	case "status", "commit", "rollback":
	default:
		return errors.New("unsupported startup transaction action")
	}
	return configTransactionCommand(bytes.NewReader(raw), output, paths)
}

// Construct only the transformation accepted by the existing boot validator.
// The remaining startup body, including user hooks, is preserved byte-for-byte.
func ipv6StartupCandidate(original, prefix []byte, container string) ([]byte, error) {
	if len(prefix) != forwardingPrefixSize || configHash(prefix) != forwardingPrefixHash {
		return nil, errors.New("untrusted IPv6 forwarding prefix")
	}
	body, ok := startupBody(original)
	if !ok {
		return nil, errors.New("unsupported startup body")
	}
	candidate := append(bytes.Clone(prefix), body...)
	if startupBootCandidateOK(original, candidate, container) {
		return candidate, nil
	}
	iface, err := protocolInterface(container)
	if err != nil {
		return nil, err
	}
	tool, path := "wg-quick", "/opt/amnezia/wireguard/wg0.conf"
	if container == "amnezia-awg2" {
		tool, path = "awg-quick", "/opt/amnezia/awg/awg0.conf"
	}
	anchor := []byte("if [ -f " + path + " ]; then (" + tool + " up " + path + "); fi\n")
	index := bytes.Index(body, anchor)
	if index < 0 {
		return nil, errors.New("unrecognized tunnel startup")
	}
	end := index + len(anchor)
	tail := body[end:]
	legacy := []byte("\namnezia_enable_ipv6 " + iface + " || exit 1\n")
	if bytes.HasPrefix(tail, legacy) {
		tail = tail[len(legacy):]
	}
	updated := append(bytes.Clone(body[:end]), []byte("\n"+startupBootCall(iface)+"\n")...)
	updated = append(updated, tail...)
	candidate = append(bytes.Clone(prefix), updated...)
	if !startupBootCandidateOK(original, candidate, container) {
		return nil, errors.New("unrecognized startup transformation")
	}
	return candidate, nil
}

// Recognize the complete known prelude, not a substring that could occur inside
// a comment, heredoc or custom shell construct. Only one post-up call is added.
func startupBootCandidateOK(original, candidate []byte, container string) bool {
	if len(candidate) < forwardingPrefixSize || configHash(candidate[:forwardingPrefixSize]) != forwardingPrefixHash {
		return false
	}
	body, ok := startupBody(original)
	if !ok {
		return false
	}
	var iface, anchor string
	var hashes []string
	switch container {
	case "amnezia-wireguard":
		iface = "wg0"
		anchor = "if [ -f /opt/amnezia/wireguard/wg0.conf ]; then (wg-quick up /opt/amnezia/wireguard/wg0.conf); fi\n"
		hashes = []string{"1e1cfdc1086bcbaf6713177312d712e5ede11fc50cb56af494608307221eea0a"}
	case "amnezia-awg2":
		iface = "awg0"
		anchor = "if [ -f /opt/amnezia/awg/awg0.conf ]; then (awg-quick up /opt/amnezia/awg/awg0.conf); fi\n"
		hashes = []string{"af19e3108f3f599ea969cf45fbaf66c6900d0cc9f7cc2db622e24e667722f7b4", "000d80cdd78d11a76f39a63b3dbf30d36a152805895375672f89ec860303359a"}
	default:
		return false
	}
	index := bytes.Index(body, []byte(anchor))
	if index < 0 {
		return false
	}
	end := index + len(anchor)
	recognized := false
	for _, hash := range hashes {
		recognized = recognized || configHash(canonicalStartupPrelude(body[:end])) == hash
	}
	if !recognized {
		return false
	}
	call := startupBootCall(iface)
	tail := body[end:]
	if bytes.HasPrefix(tail, []byte("\n"+call+"\n")) {
		return bytes.Equal(candidate[forwardingPrefixSize:], body)
	}
	legacyCall := "\namnezia_enable_ipv6 " + iface + " || exit 1\n"
	if bytes.HasPrefix(tail, []byte(legacyCall)) {
		replacement := append(bytes.Clone(body[:end]), []byte("\n"+call+"\n")...)
		replacement = append(replacement, tail[len(legacyCall):]...)
		return bytes.Equal(candidate[forwardingPrefixSize:], replacement)
	}
	if strings.Contains(string(body), call) {
		return false
	}
	replacement := append(bytes.Clone(body[:end]), []byte("\n"+call+"\n")...)
	replacement = append(replacement, tail...)
	return bytes.Equal(candidate[forwardingPrefixSize:], replacement)
}

func canonicalStartupPrelude(raw []byte) []byte {
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 6 && fields[0] == "#ifconfig" && fields[1] == "eth0:0" && fields[3] == "netmask" && fields[4] == "255.255.255.255" && fields[5] == "up" {
			if _, err := netip.ParseAddr(fields[2]); err == nil {
				lines[i] = "#ifconfig eth0:0 $SERVER_IP_ADDRESS netmask 255.255.255.255 up"
			}
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func startupBootCall(iface string) string {
	return "amnezia_enable_ipv6 " + iface + " || echo 'AMNEZIA_IPV6_FORWARDING_STATUS=boot-preparation-failed' >&2"
}

// Exact fingerprints of the shared blocks emitted by released installer paths.
// Strip recognized old definitions instead of leaving them to shadow new ones.
const currentForwardingBodySize = 2988
const currentForwardingBodyHash = "cded7cbba9e7167e67273600358bb7b8e31f752fc07aed782701a27009d34221"
const previousForwardingBodySize = 2542
const previousForwardingBodyHash = "e43c1908792f787467bb8d05ae4001a19e70a0e046b918e78a8915a3ead6826f"
const openVpnForwardingBodySize = 2547
const openVpnForwardingBodyHash = "05cfda45db89a4d9a9293c6a72899a3df3910d84e01fbbfb289267c83ab593e3"
const legacyForwardingBodySize = 1923
const legacyForwardingBodyHash = "91b5c7b6840daa721a8337a3102b1fed0e66f59498d66df3d2a0e53bfa3c7f5e"

func startupBody(original []byte) ([]byte, bool) {
	header := []byte("#!/bin/bash\n")
	if !bytes.HasPrefix(original, header) {
		return nil, false
	}
	body := original[len(header):]
	for count := 0; count < 4; count++ {
		size := 0
		if len(body) >= currentForwardingBodySize && configHash(body[:currentForwardingBodySize]) == currentForwardingBodyHash {
			size = currentForwardingBodySize
		}
		if len(body) >= previousForwardingBodySize && configHash(body[:previousForwardingBodySize]) == previousForwardingBodyHash {
			size = previousForwardingBodySize
		}
		if len(body) >= openVpnForwardingBodySize && configHash(body[:openVpnForwardingBodySize]) == openVpnForwardingBodyHash {
			size = openVpnForwardingBodySize
		}
		if len(body) >= legacyForwardingBodySize && configHash(body[:legacyForwardingBodySize]) == legacyForwardingBodyHash {
			size = legacyForwardingBodySize
		}
		if size == 0 {
			break
		}
		body = body[size:]
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "amnezia_ipv6_rule") {
			return nil, false
		}
		if strings.Contains(line, "amnezia_enable_ipv6") && line != startupBootCall("wg0") && line != startupBootCall("awg0") && line != "amnezia_enable_ipv6 wg0 || exit 1" && line != "amnezia_enable_ipv6 awg0 || exit 1" {
			return nil, false
		}
	}
	return body, true
}
