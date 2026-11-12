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

// Startup migration changes only a verified prefix. The existing script body
// remains byte-for-byte intact, and the normal file transaction retains backup.
func startupCandidateOK(original, candidate []byte) bool {
	if len(candidate) < forwardingPrefixSize || configHash(candidate[:forwardingPrefixSize]) != forwardingPrefixHash {
		return false
	}
	if len(original) >= forwardingPrefixSize && configHash(original[:forwardingPrefixSize]) == forwardingPrefixHash {
		return bytes.Equal(original, candidate)
	}
	newline := bytes.IndexByte(original, '\n')
	if newline < 0 {
		return false
	}
	header := string(original[:newline])
	if header != "#!/bin/bash" {
		return false
	}
	return bytes.Equal(candidate[forwardingPrefixSize:], original[newline+1:])
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

// Recognize the complete known prelude, not a substring that could occur inside
// a comment, heredoc or custom shell construct. Only one post-up call is added.
func startupBootCandidateOK(original, candidate []byte, container string) bool {
	if len(candidate) < forwardingPrefixSize || configHash(candidate[:forwardingPrefixSize]) != forwardingPrefixHash {
		return false
	}
	var body []byte
	if len(original) >= forwardingPrefixSize && configHash(original[:forwardingPrefixSize]) == forwardingPrefixHash {
		body = original[forwardingPrefixSize:]
	} else {
		if !bytes.HasPrefix(original, []byte("#!/bin/bash\n")) {
			return false
		}
		body = original[len("#!/bin/bash\n"):]
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
