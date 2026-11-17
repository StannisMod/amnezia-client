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
	for _, action := range []string{"apply", "apply-commit", "stage-live", "rollback-live", "prepare-forwarding", "verify-ipv6-egress", "stage-ipv6", "discard-stage", "replace-client-table", "check-client-table", "prepare-receipt", "receipt-status", "check-revoked-peer", "ack-receipt", "migrate-client-table", "prepare-peer-metadata"} {
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

func TestKnownStartupBootUpgrade(t *testing.T) {
	resource, err := os.ReadFile("../enable_ipv6_forwarding.sh")
	if err != nil {
		t.Fatal(err)
	}
	prefix := append([]byte("#!/bin/bash\n"), resource...)
	prefix = append(prefix, '\n')
	for _, spec := range []struct{ container, kind, iface string }{{"amnezia-wireguard", "wireguard", "wg0"}, {"amnezia-awg2", "awg", "awg0"}} {
		t.Run(spec.kind, func(t *testing.T) {
			current, err := os.ReadFile("../" + spec.kind + "/start.sh")
			if err != nil {
				t.Fatal(err)
			}
			call := []byte("\n" + startupBootCall(spec.iface) + "\n")
			if bytes.Count(current, call) != 1 {
				t.Fatal("canonical startup lacks unique post-up call")
			}
			old := bytes.Replace(current, call, nil, 1)
			desired := append(bytes.Clone(prefix), current[len("#!/bin/bash\n"):]...)
			deployedOld := bytes.ReplaceAll(old, []byte("$SERVER_IP_ADDRESS"), []byte("203.0.113.7"))
			deployedDesired := bytes.ReplaceAll(desired, []byte("$SERVER_IP_ADDRESS"), []byte("203.0.113.7"))
			generated, generateErr := ipv6StartupCandidate(deployedOld, prefix, spec.container)
			if generateErr != nil || !bytes.Equal(generated, deployedDesired) {
				t.Fatal("legacy boot candidate differs from verified transformation", generateErr)
			}
			if !startupBootCandidateOK(deployedOld, deployedDesired, spec.container) {
				t.Fatal("actual substituted startup prelude rejected")
			}
			fatalOld := bytes.Replace(current, call, []byte("\namnezia_enable_ipv6 "+spec.iface+" || exit 1\n"), 1)
			repaired, repairErr := ipv6StartupCandidate(fatalOld, prefix, spec.container)
			if repairErr != nil || !bytes.Equal(repaired, desired) {
				t.Fatal("fatal legacy boot generator failed", repairErr)
			}
			if !startupBootCandidateOK(fatalOld, desired, spec.container) {
				t.Fatal("fatal legacy boot call cannot be repaired")
			}
			if !startupBootCandidateOK(old, desired, spec.container) {
				t.Fatal("known old startup rejected")
			}
			maintenanceOnly := append(bytes.Clone(prefix), old[len("#!/bin/bash\n"):]...)
			if !startupBootCandidateOK(maintenanceOnly, desired, spec.container) {
				t.Fatal("maintenance-only upgrade cannot gain boot hook")
			}
			if !startupBootCandidateOK(desired, desired, spec.container) {
				t.Fatal("boot upgrade not idempotent")
			}
			if startupBootCandidateOK(old, append(bytes.Clone(desired), []byte("changed body\n")...), spec.container) {
				t.Fatal("unrelated body edit accepted")
			}
			disguised := bytes.Replace(old, []byte("echo \"Container startup\""), []byte("cat <<'EOF'\n"), 1)
			if startupBootCandidateOK(disguised, desired, spec.container) {
				t.Fatal("unknown/heredoc prelude accepted")
			}
			if startupBootCandidateOK(old, desired, "unsupported") {
				t.Fatal("unsupported container accepted")
			}
			if spec.kind == "awg" {
				start := bytes.Index(old, []byte("# Stop the route owner"))
				end := bytes.Index(old[start:], []byte("# kill daemons")) + start
				upstream := append(bytes.Clone(old[:start]), old[end:]...)
				upstreamDesired := append(bytes.Clone(prefix), bytes.Replace(upstream[len("#!/bin/bash\n"):], []byte("if [ -f /opt/amnezia/awg/awg0.conf ]; then (awg-quick up /opt/amnezia/awg/awg0.conf); fi\n"), []byte("if [ -f /opt/amnezia/awg/awg0.conf ]; then (awg-quick up /opt/amnezia/awg/awg0.conf); fi\n"+string(call)), 1)...)
				if !startupBootCandidateOK(upstream, upstreamDesired, spec.container) {
					t.Fatal("upstream pre-supervisor startup rejected")
				}
			}
		})
	}
}

func TestBootForwardingRunsAfterTunnelUp(t *testing.T) {
	resource, err := os.ReadFile("../enable_ipv6_forwarding.sh")
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile("../wireguard/start.sh")
	if err != nil {
		t.Fatal(err)
	}
	prefix := append([]byte("#!/bin/bash\n"), resource...)
	prefix = append(prefix, '\n')
	call := []byte("\n" + startupBootCall("wg0") + "\n")
	old := bytes.Replace(current, call, nil, 1)
	candidate := append(bytes.Clone(prefix), current[len("#!/bin/bash\n"):]...)
	if !startupBootCandidateOK(old, candidate, "amnezia-wireguard") {
		t.Fatal("boot candidate invalid")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "up")
	trace := filepath.Join(dir, "forwarding")
	configuration := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(configuration, nil, 0600); err != nil {
		t.Fatal(err)
	}
	scripts := map[string]string{
		"wg-quick":  "#!/bin/sh\nif [ \"$1\" = up ]; then printf up > \"$FWD_MARKER\"; fi\n",
		"ip":        "#!/bin/sh\n[ -f \"$FWD_MARKER\" ] || exit 9\nif [ \"$1\" = -o ]; then printf '2: wg0 inet6 fd77::1/64 scope global\\n'; else printf 'default dev eth0\\n'; fi\n",
		"sysctl":    "#!/bin/sh\n[ -f \"$FWD_MARKER\" ] || exit 9\nprintf prepared >> \"$FWD_TRACE\"\n",
		"ip6tables": "#!/bin/sh\n[ -f \"$FWD_MARKER\" ] || exit 9\nexit 0\n",
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Execute through the inserted call only. The rest remains validated above;
	// privileged network commands are replaced with explicit local test doubles.
	end := bytes.LastIndex(candidate, call) + len(call)
	program := bytes.ReplaceAll(candidate[:end], []byte("/opt/amnezia/wireguard/wg0.conf"), []byte(configuration))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := protocolCommand(ctx, "/bin/bash", "-s")
	command.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "FWD_MARKER=" + marker, "FWD_TRACE=" + trace}
	command.Stdin = bytes.NewReader(program)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("boot sequence failed: %v: %s", err, output)
	}
	if data, err := os.ReadFile(trace); err != nil || string(data) != "prepared" {
		t.Fatal("forwarding did not follow tunnel up", err)
	}
}

func TestPreviousOpenVpnStartupBlocksRemainRecognized(t *testing.T) {
	current, err := os.ReadFile("../enable_ipv6_forwarding.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Exact inverse of 1c903b1's reviewed no-egress OpenVPN addition.
	addition := []byte("        # OpenVPN may allocate an inner IPv6 address on an IPv4-only server.\n" +
		"        # Let the kernel return ICMPv6 no-route instead of silently dropping it.\n" +
		"        if [ \"$amnezia_v6_tunnel\" = tun0 ]; then\n" +
		"            sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null || return 1\n" +
		"            amnezia_ipv6_rule filter INPUT -i tun0 -j ACCEPT || return 1\n" +
		"            amnezia_ipv6_rule filter OUTPUT -o tun0 -j ACCEPT || return 1\n" +
		"        fi\n")
	if bytes.Count(current, addition) != 1 {
		t.Fatal("review historical startup fixture after changing its source")
	}
	openvpn := append(bytes.Replace(current, addition, nil, 1), '\n')
	previous := bytes.Replace(openvpn, []byte("wg0|awg0|tun0)"), []byte("wg0|awg0)"), 1)
	for _, fixture := range []struct {
		body []byte
		size int
		hash string
	}{
		{openvpn, openVpnForwardingBodySize, openVpnForwardingBodyHash},
		{previous, previousForwardingBodySize, previousForwardingBodyHash},
	} {
		if len(fixture.body) != fixture.size || configHash(fixture.body) != fixture.hash {
			t.Fatal("historical source fingerprint differs")
		}
		body := []byte("# preserved administrator hook\nexit 23\n")
		original := append(append([]byte("#!/bin/bash\n"), fixture.body...), body...)
		got, ok := startupBody(original)
		if !ok || !bytes.Equal(got, body) {
			t.Fatal("previous block not removed without changing administrator body")
		}
		tampered := bytes.Clone(original)
		tampered[len("#!/bin/bash\n")+bytes.Index(fixture.body, []byte("amnezia_ipv6_rule"))] = 'X'
		if _, ok := startupBody(tampered); ok {
			t.Fatal("unrecognized forwarding definition accepted")
		}
	}
}

func TestHistoricalStartupPrefixReplacement(t *testing.T) {
	legacy, err := os.ReadFile("testdata/ipv6-forwarding-legacy.sh")
	if err != nil {
		t.Fatal(err)
	}
	legacy = append(legacy, '\n')
	if len(legacy) != legacyForwardingBodySize || configHash(legacy) != legacyForwardingBodyHash {
		t.Fatal("historical fixture fingerprint drift")
	}
	current, err := os.ReadFile("../enable_ipv6_forwarding.sh")
	if err != nil {
		t.Fatal(err)
	}
	current = append(current, '\n')
	if len(current) != currentForwardingBodySize || configHash(current) != currentForwardingBodyHash {
		t.Fatal("current block fingerprint drift")
	}
	header := []byte("#!/bin/bash\n")
	body := []byte("# original custom body preserved\nexit 23\n")
	desired := append(append(bytes.Clone(header), current...), body...)
	original := append(append(bytes.Clone(header), legacy...), body...)
	if !startupCandidateOK(original, desired) {
		t.Fatal("historical definitions cannot be replaced")
	}
	nested := append(append(append(bytes.Clone(header), current...), legacy...), body...)
	if !startupCandidateOK(nested, desired) {
		t.Fatal("previous prepend upgrade leaves old definitions shadowing current ones")
	}
	for _, definition := range []string{"amnezia_enable_ipv6 () { :; }\n", "function amnezia_enable_ipv6 { :; }\n"} {
		unknownBody := append([]byte(definition), body...)
		unknown := append(bytes.Clone(header), unknownBody...)
		proposed := append(append(bytes.Clone(header), current...), unknownBody...)
		if startupCandidateOK(unknown, proposed) {
			t.Fatal("unknown function definition accepted")
		}
	}
	modified := bytes.Clone(original)
	modified[len(header)+1] ^= 1
	if startupCandidateOK(modified, desired) {
		t.Fatal("unknown historical definition changed implicitly")
	}
	if startupCandidateOK(original, append(bytes.Clone(desired), []byte("changed body\n")...)) {
		t.Fatal("historical upgrade rewrote body")
	}
	template, err := os.ReadFile("../wireguard/start.sh")
	if err != nil {
		t.Fatal(err)
	}
	deployedBody := template[len(header):]
	desired = append(append(bytes.Clone(header), current...), deployedBody...)
	oldBody := bytes.Replace(deployedBody, []byte("\n"+startupBootCall("wg0")+"\n"), []byte("\namnezia_enable_ipv6 wg0 || exit 1\n"), 1)
	original = append(append(bytes.Clone(header), legacy...), oldBody...)
	if !startupBootCandidateOK(original, desired, "amnezia-wireguard") {
		t.Fatal("historical prefix and fatal boot hook cannot be upgraded together")
	}
}
