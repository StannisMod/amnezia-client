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

type ipv6UpgradeDocker struct {
	t                                       *testing.T
	stateDir                                string
	current, original                       []byte
	stage                                   map[string]any
	applied, verified, signed               bool
	failEgress, losePublication, loseCommit bool
	publications, rollbacks                 int
}

func (f *ipv6UpgradeDocker) call(ctx context.Context, args []string, input []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if args[0] == "inspect" {
		switch args[2] {
		case "{{.Id}}":
			return []byte(strings.Repeat("a", 64)), nil
		case "{{.Image}}":
			return []byte("owned-delivery-image"), nil
		default:
			return []byte("1"), nil
		}
	}
	if args[0] == "run" {
		var req request
		if json.Unmarshal(input, &req) != nil {
			f.t.Fatal("invalid delivery request")
		}
		action := args[len(args)-1]
		if action == "publish-ipv6-if" && !f.verified {
			f.t.Fatal("published IPv6 before authenticated egress")
		}
		response, err := admin(f.stateDir, action, req)
		if err != nil {
			return nil, err
		}
		if action == "publish-ipv6-if" {
			f.publications++
			if f.losePublication {
				f.losePublication = false
				return nil, errors.New("lost publication response")
			}
		}
		return mustJSON(response), nil
	}
	if args[0] == "exec" && args[2] == "sh" {
		digest := strings.Repeat("e", 64)
		return append([]byte(digest+"  /opt/amnezia/config-helper\n"), mustJSON(map[string]any{"version": 1, "installed": digest, "candidate": digest})...), nil
	}
	if args[0] == "exec" && args[2] == "head" {
		return bytes.Clone(f.current), nil
	}
	if args[0] != "exec" || args[1] != "-i" {
		f.t.Fatalf("unexpected Docker operation: %v", args)
	}
	var req configTransactionRequest
	if json.Unmarshal(input, &req) != nil {
		f.t.Fatal("invalid helper request")
	}
	if req.Action == "capabilities" {
		return mustJSON(map[string]any{"version": 1, "features": []string{"ipv6-egress-v1"}}), nil
	}
	if req.Action == "check-ipv6-live" || req.Action == "check-live" {
		if f.stage != nil || !f.applied || !bytes.Equal(req.Expected, f.current) {
			return nil, errors.New("not current")
		}
		return mustJSON(map[string]any{"version": 1, "current": true}), nil
	}
	if req.Action == "stage-ipv6" {
		if f.stage != nil || !bytes.Equal(req.Expected, f.current) {
			return nil, errors.New("conflict")
		}
		plan, err := planIPv6Config(f.current, req.ServerIPv6)
		if err != nil {
			return nil, err
		}
		f.original = bytes.Clone(f.current)
		f.current = plan.Config
		f.stage = map[string]any{"version": 1, "operation": strings.Repeat("2", 64), "originalHash": configHash(f.original), "candidateHash": configHash(f.current), "serverIpv6": req.ServerIPv6, "clientIpv6": plan.Assignments}
		return mustJSON(f.stage), nil
	}
	if f.stage == nil {
		return nil, errors.New("no pending transaction")
	}
	if req.Action == "status" {
		return mustJSON(f.stage), nil
	}
	if req.Operation != f.stage["operation"] {
		return nil, errors.New("wrong operation")
	}
	switch req.Action {
	case "apply":
		f.applied = true
	case "verify-ipv6-egress":
		if !f.applied {
			f.t.Fatal("measured before applying IPv6")
		}
		if f.failEgress {
			return nil, errors.New("unreachable")
		}
		f.verified = true
	case "commit":
		if !f.applied || !f.verified || (f.signed && f.publications == 0) {
			f.t.Fatal("committed before readiness/publication")
		}
		f.stage = nil
		if f.loseCommit {
			f.loseCommit = false
			return nil, errors.New("lost commit response")
		}
	case "rollback-live":
		if f.publications != 0 {
			f.t.Fatal("rolled back published IPv6")
		}
		f.current = bytes.Clone(f.original)
		f.stage = nil
		f.applied = false
		f.rollbacks++
	default:
		f.t.Fatalf("unexpected helper operation %q", req.Action)
	}
	return mustJSON(map[string]any{"version": 1, "ok": true}), nil
}

func ipv6UpgradeFixture(t *testing.T, container string, signed bool) (*ipv6UpgradeEngine, *ipv6UpgradeDocker) {
	t.Helper()
	dir := t.TempDir()
	info := mustAdmin(t, dir, "init", request{Host: "vpn.example.test"})
	mustAdmin(t, dir, "issue", request{Container: container, ClientPublicKey: testKey('A'), Settings: testSettings("original.example.test")})
	config := []byte("[Interface]\nPrivateKey = " + testKey('P') + "\nAddress = 10.77.0.1/24\nListenPort = 51820\n[Peer]\nPublicKey = " + testKey('A') + "\nAllowedIPs = 10.77.0.2/32\n")
	fake := &ipv6UpgradeDocker{t: t, stateDir: dir, current: config, signed: signed}
	req := ipv6UpgradeRequest{Container: container}
	if signed {
		raw := mustJSON(info)
		var response map[string]json.RawMessage
		_ = json.Unmarshal(raw, &response)
		req.ExpectedPublicKey = rawString(response["publicKey"])
		req.ExpectedCertificate = rawString(response["certificate"])
	}
	return &ipv6UpgradeEngine{docker: fake.call, dir: t.TempDir(), req: req}, fake
}

func resumeIPv6Upgrade(t *testing.T, e *ipv6UpgradeEngine) *ipv6UpgradeEngine {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.dir, "intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	retry := &ipv6UpgradeEngine{docker: e.docker, dir: e.dir, req: e.req}
	if json.Unmarshal(raw, &retry.intent) != nil || !validIPv6UpgradeIntent(retry.intent) {
		t.Fatal("invalid durable activation intent")
	}
	if bytes.Contains(raw, []byte(testKey('P'))) {
		t.Fatal("activation intent duplicated protocol private key")
	}
	return retry
}

func TestIPv6UpgradePublishesOnlyAfterReadiness(t *testing.T) {
	for _, container := range []string{"amnezia-wireguard", "amnezia-awg2"} {
		for _, signed := range []bool{false, true} {
			t.Run(container+map[bool]string{true: "-signed", false: "-native"}[signed], func(t *testing.T) {
				e, f := ipv6UpgradeFixture(t, container, signed)
				before := bytes.Clone(f.current)
				result := e.execute(context.Background())
				if result.Result != "applied" {
					t.Fatal(result)
				}
				if f.rollbacks != 0 || !f.verified || !strings.Contains(string(f.current), "10.77.0.2/32, fd") {
					t.Fatal("IPv4 identity or IPv6 assignment lost")
				}
				if !bytes.Contains(before, []byte("PrivateKey = "+testKey('P'))) || !bytes.Contains(f.current, []byte("PrivateKey = "+testKey('P'))) {
					t.Fatal("private identity changed")
				}
				retry := resumeIPv6Upgrade(t, e)
				if result = retry.execute(context.Background()); result.Result != "applied" || result.Reason != "ipv6_already_applied" {
					t.Fatal(result)
				}
				if signed && f.publications != 1 {
					t.Fatal("retry republished client revisions", f.publications)
				}
			})
		}
	}
}

func TestIPv6UpgradeFailedEgressRestoresUnpublishedState(t *testing.T) {
	e, f := ipv6UpgradeFixture(t, "amnezia-wireguard", true)
	before := bytes.Clone(f.current)
	f.failEgress = true
	result := e.execute(context.Background())
	if result.Result != "rolled_back" || f.rollbacks != 1 || f.publications != 0 || !bytes.Equal(before, f.current) {
		t.Fatal("unpublished migration not restored", result)
	}
	resumeIPv6Upgrade(t, e)
}

func TestIPv6UpgradeLostPublicationRecoversForwardPreservingNewSettings(t *testing.T) {
	e, f := ipv6UpgradeFixture(t, "amnezia-awg2", true)
	f.losePublication = true
	result := e.execute(context.Background())
	if result.Result != "pending" || f.rollbacks != 0 {
		t.Fatal(result)
	}
	updated := testSettings("newer.example.test")
	mustAdmin(t, f.stateDir, "publish", request{Container: e.req.Container, Settings: updated})
	retry := resumeIPv6Upgrade(t, e)
	f.loseCommit = true
	result = retry.execute(context.Background())
	if result.Result != "pending" || f.rollbacks != 0 {
		t.Fatal(result)
	}
	retry = resumeIPv6Upgrade(t, retry)
	result = retry.execute(context.Background())
	if result.Result != "applied" || f.rollbacks != 0 {
		t.Fatal(result)
	}
	state, err := readState(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range state.Records {
		if !bytes.Equal(record.Settings, updated) || record.ClientIPv6 == nil || *record.ClientIPv6 != retry.intent.Assignments[record.ClientPublicKey] {
			t.Fatal("forward recovery overwrote newer settings or lost IPv6")
		}
	}
}
