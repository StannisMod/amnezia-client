package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRolloutDocker struct {
	t           *testing.T
	stateDir    string
	saved, live []byte
	fail        string
	original    []byte
	configReads int
	restarts    int
	published   bool
}

func (f *fakeRolloutDocker) call(ctx context.Context, args []string, input []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if args[0] == "inspect" {
		switch args[2] {
		case "{{.HostConfig.NetworkMode}}":
			return []byte("bridge"), nil
		case "{{json .Mounts}}":
			return []byte("[]"), nil
		case "{{json .HostConfig.PortBindings}}":
			return []byte(`{"51820/udp":[{"HostIp":"0.0.0.0","HostPort":"51820"}]}`), nil

		case "{{.Id}}":
			return []byte("target-id"), nil
		case "{{.State.Running}}":
			return []byte("true"), nil
		case "{{.Image}}":
			return []byte("delivery-image"), nil
		default:
			return []byte("1"), nil
		}
	}
	if args[0] == "run" {
		var req request
		if json.Unmarshal(input, &req) != nil {
			f.t.Fatal("invalid request")
		}
		action := args[len(args)-1]
		if (action == "publish-if" || action == "publish-if-live") && f.fail == "before-publication" {
			return nil, errors.New("injected")
		}
		result, err := admin(f.stateDir, action, req)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(result)
		if action == "publish-if" || action == "publish-if-live" {
			f.published = true
			if f.fail == "after-publication" {
				return nil, errors.New("lost response")
			}
		}
		return raw, err
	}
	if args[0] == "cp" {
		data, err := os.ReadFile(args[1])
		if err != nil {
			return nil, err
		}
		if f.fail == "copy" && !bytes.Equal(data, f.original) {
			return nil, errors.New("injected")
		}
		f.saved = data
		return nil, nil
	}
	if args[0] == "restart" {
		f.restarts++
		if f.fail == "restart" && f.restarts == 1 {
			return nil, errors.New("injected")
		}
		if f.fail == "rollback" {
			return nil, errors.New("injected")
		}
		f.live = append([]byte(nil), f.saved...)
		return nil, nil
	}
	if args[0] == "exec" {
		command := args[2:]
		if args[1] == "-i" {
			command = args[3:]
		}
		switch command[0] {
		case "/updates":
			var req request
			json.Unmarshal(input, &req)
			state, e := readState(f.stateDir)
			if e != nil {
				return nil, e
			}
			result := info(state)
			result["notReady"] = 0
			if f.fail == "unready" {
				result["notReady"] = 1
			}
			return json.Marshal(result)
		case "test":
			if f.fail == "kernel" {
				return nil, errors.New("no userspace tun")
			}
			return nil, nil
		case "sh":
			if f.fail == "old-daemon" {
				return nil, errors.New("wrong daemon")
			}
			return nil, nil
		case "cat":
			f.configReads++
			if f.fail == "concurrent-change" && f.configReads > 1 {
				f.saved = bytes.ReplaceAll(f.saved, []byte("10.87.0.2/32"), []byte("10.87.0.3/32"))
			}
			return f.saved, nil
		case "awg-quick":
			return f.saved, nil
		case "awg":
			if len(command) > 2 && command[1] == "showconf" {
				return f.live, nil
			}
			if len(command) > 3 && command[3] == "public-key" {
				return []byte(testKey('P')), nil
			}
			return nil, nil
		}
	}
	f.t.Fatalf("unexpected command %v", args)
	return nil, errors.New("unexpected command")
}
func rolloutFixture(t *testing.T, mode string) (*rolloutEngine, *fakeRolloutDocker) {
	t.Helper()
	dir := t.TempDir()
	info := mustAdmin(t, dir, "init", request{Host: "vpn.example.test"})
	peer := testKey('C')
	saved := []byte("[Interface]\nPrivateKey = " + testKey('S') + "\nListenPort = 51820\nS1 = 0\nS2 = 68\nS3 = 0\nS4 = 0\nH1 = 1001-1010\nH2 = 2001-2010\nH3 = 3001-3010\nH4 = 4001-4010\n\n[Peer]\nPublicKey = " + peer + "\nPresharedKey = " + testKey('K') + "\nAllowedIPs = 10.87.0.2/32\n")
	if mode != "uncovered" {
		mustAdmin(t, dir, "issue", request{Container: rolloutContainer, ClientPublicKey: peer, Settings: testSettings("vpn.example.test")})
	}
	encoded, _ := json.Marshal(info)
	var bootstrap map[string]json.RawMessage
	json.Unmarshal(encoded, &bootstrap)
	var public, cert string
	json.Unmarshal(bootstrap["publicKey"], &public)
	json.Unmarshal(bootstrap["certificate"], &cert)
	fake := &fakeRolloutDocker{t: t, stateDir: dir, saved: saved, live: saved, original: saved, fail: mode}
	engine := &rolloutEngine{docker: fake.call, work: t.TempDir(), req: rolloutRequest{Host: "vpn.example.test", ExpectedPublicKey: public, ExpectedCertificate: cert}}
	return engine, fake
}
func TestRolloutPreservesPeerIdentity(t *testing.T) {
	engine, docker := rolloutFixture(t, "")
	beforeFields, peers, e := iniInterface(docker.live)
	if e != nil {
		t.Fatal(e)
	}
	result := engine.execute(context.Background())
	if result.Result != "applied" {
		t.Fatalf("unexpected outcome %s/%s", result.Result, result.Reason)
	}
	fields, afterPeers, e := iniInterface(docker.live)
	if e != nil {
		t.Fatal(e)
	}
	if fields["PrivateKey"] != beforeFields["PrivateKey"] || strings.Join(peers, ",") != strings.Join(afterPeers, ",") {
		t.Fatal("identity changed")
	}
	if !bytes.Contains(docker.live, []byte("PresharedKey = "+testKey('K'))) || !bytes.Contains(docker.live, []byte("AllowedIPs = 10.87.0.2/32")) {
		t.Fatal("peer association changed")
	}
	if !keyOK(fields["HeaderProtectionKey"]) || fields["S1"] != "12" || fields["S2"] != "69" || fields["S3"] != "12" || fields["S4"] != "12" {
		t.Fatal("invalid protection padding")
	}
	state, e := readState(docker.stateDir)
	if e != nil {
		t.Fatal(e)
	}
	for _, rec := range state.Records {
		if rec.Revision != 2 || !bytes.Contains(rec.Settings, []byte("HeaderProtectionKey")) {
			t.Fatal("protected settings not published")
		}
	}
}
func TestRolloutFaults(t *testing.T) {
	for _, mode := range []string{"kernel", "old-daemon", "uncovered", "unready", "concurrent-change", "copy", "restart", "before-publication", "after-publication", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			engine, docker := rolloutFixture(t, mode)
			result := engine.execute(context.Background())
			if mode == "kernel" || mode == "old-daemon" || mode == "uncovered" || mode == "unready" || mode == "concurrent-change" {
				if result.Result != "rejected" || docker.restarts != 0 {
					t.Fatal("unsupported server was mutated")
				}
				return
			}
			if mode == "rollback" {
				if result.Result != "rollback_failed" {
					t.Fatal("rollback failure hidden")
				}
				return
			}
			if result.Result != "rolled_back" || !bytes.Equal(docker.saved, docker.original) || !bytes.Equal(docker.live, docker.original) {
				t.Fatalf("original VPN not restored: %s", result.Result)
			}
			state, e := readState(docker.stateDir)
			if e != nil {
				t.Fatal(e)
			}
			for _, rec := range state.Records {
				if bytes.Contains(rec.Settings, []byte("HeaderProtectionKey")) {
					t.Fatal("rollback left protected feed")
				}
				if docker.published && rec.Revision != 3 {
					t.Fatal("rollback did not advance signed revision")
				}
			}
			audit, e := os.ReadFile(filepath.Join(engine.work, "result.json"))
			if e != nil || bytes.Contains(audit, []byte("PrivateKey")) || bytes.Contains(audit, []byte("PresharedKey")) {
				t.Fatal("audit is missing or contains device secrets")
			}
		})
	}
}

func TestCanonicalConfigAllowsOnlyKnownZeroDefaults(t *testing.T) {
	engine, fake := rolloutFixture(t, "")
	omitted := strings.ReplaceAll(string(fake.saved), "S1 = 0\n", "")
	omitted = strings.ReplaceAll(omitted, "S3 = 0\n", "")
	omitted = strings.ReplaceAll(omitted, "S4 = 0\n", "")
	fake.live = []byte(omitted)
	result := engine.execute(context.Background())
	if result.Result != "applied" {
		t.Fatalf("zero defaults rejected: %s/%s", result.Result, result.Reason)
	}
	before, _ := canonicalConfig(fake.original)
	changed := strings.ReplaceAll(string(fake.original), "AllowedIPs = 10.87.0.2/32", "AllowedIPs = 10.87.0.3/32")
	after, _ := canonicalConfig([]byte(changed))
	if before == after {
		t.Fatal("peer routing change ignored")
	}
}

func TestActiveProtectionRetryDoesNotRotateOrRestart(t *testing.T) {
	engine, fake := rolloutFixture(t, "")
	result := engine.execute(context.Background())
	if result.Result != "applied" {
		t.Fatal(result.Result)
	}
	before := append([]byte(nil), fake.live...)
	restarts := fake.restarts
	retry := rolloutEngine{docker: fake.call, work: t.TempDir(), req: engine.req}
	result = retry.execute(context.Background())
	if result.Result != "applied" || !bytes.Equal(before, fake.live) || fake.restarts != restarts {
		t.Fatal("retry disrupted an active protected interface")
	}
}
