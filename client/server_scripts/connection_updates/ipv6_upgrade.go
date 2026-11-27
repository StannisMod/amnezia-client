package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type ipv6UpgradeRequest struct {
	Container           string `json:"container"`
	ForwardingPrefix    string `json:"forwardingPrefix,omitempty"`
	ExpectedPublicKey   string `json:"expectedPublicKey,omitempty"`
	ExpectedCertificate string `json:"expectedCertificate,omitempty"`
}

// Only hashes, public assignments and operation identities are persisted here.
// The protocol helper already owns the private original/candidate snapshots.
type ipv6UpgradeIntent struct {
	Version              int                `json:"version"`
	Request              ipv6UpgradeRequest `json:"request"`
	Target               string             `json:"target"`
	CIDR                 string             `json:"cidr"`
	OriginalHash         string             `json:"originalHash"`
	CandidateHash        string             `json:"candidateHash"`
	Assignments          map[string]string  `json:"assignments"`
	Operation            string             `json:"operation"`
	Publication          string             `json:"publication"`
	ExpectedState        string             `json:"expectedState"`
	PublicationAttempted bool               `json:"publicationAttempted"`
	Phase                string             `json:"phase"`
	StartupOriginalHash  string             `json:"startupOriginalHash,omitempty"`
	StartupCandidateHash string             `json:"startupCandidateHash,omitempty"`
	StartupOperation     string             `json:"startupOperation,omitempty"`
	StartupPrepared      bool               `json:"startupPrepared,omitempty"`
}

type ipv6UpgradeEngine struct {
	docker        dockerRunner
	dir           string
	req           ipv6UpgradeRequest
	intent        ipv6UpgradeIntent
	deliveryImage string
}

func (e *ipv6UpgradeEngine) call(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	engine := rolloutEngine{docker: e.docker}
	return engine.call(ctx, input, args...)
}
func (e *ipv6UpgradeEngine) helper(ctx context.Context, req configTransactionRequest) (map[string]json.RawMessage, error) {
	return e.transaction(ctx, req, "config-file-transaction")
}
func (e *ipv6UpgradeEngine) transaction(ctx context.Context, req configTransactionRequest, command string) (map[string]json.RawMessage, error) {
	req.Container = e.req.Container
	out, err := e.call(ctx, mustJSON(req), "exec", "-i", e.intent.Target, "/opt/amnezia/config-helper", command)
	if err != nil {
		return nil, errors.New("protocol operation not confirmed")
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(out, &response) != nil || string(response["version"]) != "1" {
		return nil, errors.New("invalid protocol response")
	}
	return response, nil
}

// Boot preparation is a separate compatible transaction: it never executes the
// startup body, and remains installed if an unpublished IPv6 activation rolls back.
func (e *ipv6UpgradeEngine) prepareStartup(ctx context.Context) error {
	if e.req.ForwardingPrefix == "" {
		return nil
	} // Older direct CLI callers prepare deployment themselves.
	prefix := []byte(e.req.ForwardingPrefix)
	current, err := e.call(ctx, nil, "exec", e.intent.Target, "head", "-c", "4194305", "/opt/amnezia/start.sh")
	if err != nil || len(current) > 4<<20 {
		return errors.New("cannot read startup")
	}
	candidate, err := ipv6StartupCandidate(current, prefix, e.req.Container)
	if err != nil {
		return err
	}
	invoke := func(req configTransactionRequest) (map[string]json.RawMessage, error) {
		return e.transaction(ctx, req, "startup-file-transaction")
	}
	check := func() error {
		_, err := invoke(configTransactionRequest{Action: "check-current", Expected: candidate})
		return err
	}
	if (e.intent.StartupPrepared || e.intent.StartupOriginalHash == "") && bytes.Equal(current, candidate) {
		return check()
	}
	if e.intent.StartupPrepared {
		e.intent.StartupPrepared = false
		e.intent.StartupOriginalHash = ""
		e.intent.StartupCandidateHash = ""
		e.intent.StartupOperation = ""
	}
	if e.intent.StartupOriginalHash == "" {
		e.intent.StartupOriginalHash = configHash(current)
		e.intent.StartupCandidateHash = configHash(candidate)
		if err = e.save(e.intent.Phase); err != nil {
			return err
		}
	}
	matches := func(response map[string]json.RawMessage) bool {
		operation := rawString(response["operation"])
		return configOperationOK(operation) && rawString(response["originalHash"]) == e.intent.StartupOriginalHash && rawString(response["candidateHash"]) == e.intent.StartupCandidateHash && (e.intent.StartupOperation == "" || operation == e.intent.StartupOperation)
	}
	status, statusErr := invoke(configTransactionRequest{Action: "status"})
	if statusErr == nil && matches(status) {
		e.intent.StartupOperation = rawString(status["operation"])
	} else if e.intent.StartupOperation == "" && configHash(current) == e.intent.StartupOriginalHash && configHash(candidate) == e.intent.StartupCandidateHash {
		status, err = invoke(configTransactionRequest{Action: "stage", Expected: current, Candidate: candidate})
		if err != nil {
			status, err = invoke(configTransactionRequest{Action: "status"})
		}
		if err != nil || !matches(status) {
			return errors.New("startup stage not confirmed")
		}
		e.intent.StartupOperation = rawString(status["operation"])
	} else if configHash(current) == e.intent.StartupCandidateHash && e.intent.StartupOperation != "" && check() == nil {
		e.intent.StartupPrepared = true
		return e.save(e.intent.Phase)
	} else {
		return errors.New("startup transaction identity changed")
	}
	if err = e.save(e.intent.Phase); err != nil {
		return err
	}
	if _, err = invoke(configTransactionRequest{Action: "commit", Operation: e.intent.StartupOperation}); err != nil && check() != nil {
		return errors.New("startup commit not confirmed")
	}
	if err = check(); err != nil {
		return err
	}
	e.intent.StartupPrepared = true
	return e.save(e.intent.Phase)
}

func (e *ipv6UpgradeEngine) feed(ctx context.Context, action string, req request) (map[string]json.RawMessage, error) {
	engine := rolloutEngine{docker: e.docker, deliveryImage: e.deliveryImage}
	return engine.feed(ctx, action, req)
}
func (e *ipv6UpgradeEngine) save(phase string) error {
	e.intent.Phase = phase
	return writeConfigAtomic(filepath.Join(e.dir, "intent.json"), mustJSON(e.intent), 0600, os.Geteuid(), os.Getegid(), false)
}
func rawString(value json.RawMessage) string {
	var result string
	_ = json.Unmarshal(value, &result)
	return result
}
func rawBool(value json.RawMessage) bool {
	var result bool
	_ = json.Unmarshal(value, &result)
	return result
}

func upgradeServerCIDR(raw []byte) (string, error) {
	section := ""
	result := ""
	for _, original := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(strings.SplitN(original, "#", 2)[0])
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		field := strings.SplitN(line, "=", 2)
		if section != "[Interface]" || len(field) != 2 || strings.TrimSpace(field[0]) != "Address" {
			continue
		}
		for _, value := range strings.Split(field[1], ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
			if err != nil {
				return "", errors.New("invalid protocol address")
			}
			if !prefix.Addr().Is6() {
				continue
			}
			if result != "" || prefix.Bits() != 64 || !clientIPv6OK(prefix.Addr().String()) {
				return "", errors.New("unsupported existing IPv6 address")
			}
			result = prefix.String()
		}
	}
	if result != "" {
		return result, nil
	}
	var address [16]byte
	address[0] = 0xfd
	address[15] = 1
	if _, err := rand.Read(address[1:6]); err != nil {
		return "", err
	}
	return netip.PrefixFrom(netip.AddrFrom16(address), 64).String(), nil
}

func (e *ipv6UpgradeEngine) matchesStage(response map[string]json.RawMessage) bool {
	var assignments map[string]string
	if json.Unmarshal(response["clientIpv6"], &assignments) != nil {
		return false
	}
	return configOperationOK(rawString(response["operation"])) && rawString(response["originalHash"]) == e.intent.OriginalHash &&
		rawString(response["candidateHash"]) == e.intent.CandidateHash && rawString(response["serverIpv6"]) == e.intent.CIDR &&
		bytes.Equal(mustJSON(assignments), mustJSON(e.intent.Assignments)) && (e.intent.Operation == "" || e.intent.Operation == rawString(response["operation"]))
}

// Deployment must prepare network attachment and the verified startup prefix
// before calling this command. This coordinator never tears down a
// tunnel, replaces keys, detaches a network, or runs a startup script body.
func (e *ipv6UpgradeEngine) execute(ctx context.Context) (result rolloutResult) {
	result = rolloutResult{Version: 1, Result: "rejected", Reason: "ipv6_preflight_failed"}
	ownedStage := false
	defer func() {
		if !ownedStage || result.Result == "applied" || e.intent.Operation == "" || e.intent.Phase == "complete" || e.intent.Phase == "committing" || e.intent.PublicationAttempted {
			return
		}
		recovery, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := e.helper(recovery, configTransactionRequest{Action: "rollback-live", Operation: e.intent.Operation}); err == nil {
			if e.save("rolled_back") == nil {
				result.Result = "rolled_back"
				return
			}
		}
		result.Result = "recovery_required"
	}()
	if e.req.ForwardingPrefix != "" && (len(e.req.ForwardingPrefix) != forwardingPrefixSize || configHash([]byte(e.req.ForwardingPrefix)) != forwardingPrefixHash) {
		return
	}
	if !containerOK(e.req.Container) || (e.req.ExpectedPublicKey == "") != (e.req.ExpectedCertificate == "") {
		return
	}
	inspect, err := e.call(ctx, nil, "inspect", "-f", "{{.Id}}", e.req.Container)
	if err != nil {
		return
	}
	target := strings.TrimSpace(string(inspect))
	if !configOperationOK(target) {
		return
	}
	if e.intent.Version != 0 && e.intent.Phase != "rolled_back" {
		if e.intent.Phase == "complete" && e.intent.Request.Container == e.req.Container && (e.intent.Request != e.req || e.intent.Target != target) {
			e.intent = ipv6UpgradeIntent{Version: 1, Request: e.req, Target: target}
		} else if e.intent.Request != e.req || e.intent.Target != target {
			result.Reason = "ipv6_intent_identity_changed"
			return
		}
	} else {
		e.intent = ipv6UpgradeIntent{Version: 1, Request: e.req, Target: target}
	}
	// Do not execute an unowned helper, even if it advertises the right APIs.
	identity, err := e.call(ctx, nil, "exec", target, "sh", "-ec", `test ! -L /opt/amnezia/config-helper && test ! -L /opt/amnezia/config-helper.amnezia-owner && test "$(stat -c '%u %a %h' /opt/amnezia/config-helper)" = '0 700 1' && test "$(stat -c '%u %a %h' /opt/amnezia/config-helper.amnezia-owner)" = '0 600 1' && sha256sum /opt/amnezia/config-helper && cat /opt/amnezia/config-helper.amnezia-owner`)
	if err != nil {
		return
	}
	parts := bytes.SplitN(identity, []byte("\n"), 2)
	var owner struct {
		Version              int
		Installed, Candidate string
	}
	if len(parts) != 2 || len(bytes.Fields(parts[0])) != 2 || json.Unmarshal(parts[1], &owner) != nil || owner.Version != 1 {
		return
	}
	digest := string(bytes.Fields(parts[0])[0])
	if !configOperationOK(digest) || (digest != owner.Installed && digest != owner.Candidate) {
		return
	}
	capabilities, err := e.helper(ctx, configTransactionRequest{Action: "capabilities"})
	if err != nil {
		return
	}
	var features []string
	_ = json.Unmarshal(capabilities["features"], &features)
	supported := false
	bootSupported := false
	for _, feature := range features {
		supported = supported || feature == "ipv6-egress-v1"
		bootSupported = bootSupported || feature == "ipv6-boot-upgrade-v1"
	}
	if !supported || (e.req.ForwardingPrefix != "" && !bootSupported) {
		result.Reason = "protocol_helper_upgrade_required"
		return
	}
	var info map[string]json.RawMessage
	if e.req.ExpectedPublicKey != "" {
		label, err := e.call(ctx, nil, "inspect", "-f", `{{index .Config.Labels "org.amnezia.connection-updates"}}`, deliveryContainer)
		if err != nil || strings.TrimSpace(string(label)) != "1" {
			return
		}
		image, err := e.call(ctx, nil, "inspect", "-f", "{{.Image}}", deliveryContainer)
		if err != nil {
			return
		}
		e.deliveryImage = strings.TrimSpace(string(image))
		info, err = e.feed(ctx, "info", request{})
		if err != nil || rawString(info["publicKey"]) != e.req.ExpectedPublicKey || rawString(info["certificate"]) != e.req.ExpectedCertificate {
			result.Reason = "delivery_identity_changed"
			return
		}
		var deliveryFeatures []string
		if json.Unmarshal(info["features"], &deliveryFeatures) != nil {
			return
		}
		conditional := false
		for _, feature := range deliveryFeatures {
			conditional = conditional || feature == "conditional-client-ipv6-v1"
		}
		if !conditional {
			result.Reason = "delivery_service_upgrade_required"
			return
		}
	}
	configPath := "/opt/amnezia/wireguard/wg0.conf"
	if e.req.Container == "amnezia-awg2" {
		configPath = "/opt/amnezia/awg/awg0.conf"
	}
	current, err := e.call(ctx, nil, "exec", target, "head", "-c", "4194305", configPath)
	if err != nil || len(current) > 4<<20 {
		return
	}
	if e.intent.Phase == "complete" && configHash(current) == e.intent.CandidateHash {
		if err = e.prepareStartup(ctx); err != nil {
			result.Result = "pending"
			result.Reason = "ipv6_boot_preparation_unconfirmed"
			return
		}
	}
	if e.intent.Phase == "complete" {
		check := configTransactionRequest{Action: "check-live", Expected: current}
		if configHash(current) == e.intent.CandidateHash {
			check.Action = "check-ipv6-live"
			check.ServerIPv6 = e.intent.CIDR
		}
		if _, err = e.helper(ctx, check); err != nil {
			return
		}
		if configHash(current) == e.intent.CandidateHash {
			result.Result = "applied"
			result.Reason = "ipv6_already_applied"
			return
		}
		// A completed activation must not permanently reserve the protocol:
		// start from the currently verified snapshot after normal peer edits.
		e.intent = ipv6UpgradeIntent{Version: 1, Request: e.req, Target: target}
	}
	if e.intent.CIDR == "" {
		cidr, err := upgradeServerCIDR(current)
		if err != nil {
			return
		}
		plan, err := planIPv6Config(current, cidr)
		if err != nil {
			return
		}
		e.intent.CIDR = cidr
		e.intent.OriginalHash = configHash(current)
		e.intent.CandidateHash = configHash(plan.Config)
		e.intent.Assignments = plan.Assignments
		if e.req.ExpectedPublicKey != "" {
			e.intent.Publication, err = randomHex(32)
			if err != nil {
				return
			}
			e.intent.ExpectedState = rawString(info["stateTag"])
			if !configOperationOK(e.intent.ExpectedState) {
				return
			}
		}
		if e.save("prepared") != nil {
			return
		}
	}
	if err = e.prepareStartup(ctx); err != nil {
		result.Result = "pending"
		result.Reason = "ipv6_boot_preparation_unconfirmed"
		return
	}
	// A lost stage reply is recovered only by the exact original/candidate,
	// server address and public assignments, never merely by finding a journal.
	status, statusErr := e.helper(ctx, configTransactionRequest{Action: "status"})
	if statusErr == nil && e.matchesStage(status) {
		e.intent.Operation = rawString(status["operation"])
	} else if e.intent.Operation == "" && configHash(current) == e.intent.OriginalHash {
		status, err = e.helper(ctx, configTransactionRequest{Action: "stage-ipv6", Expected: current, ServerIPv6: e.intent.CIDR})
		if err != nil {
			status, err = e.helper(ctx, configTransactionRequest{Action: "status"})
		}
		if err != nil || !e.matchesStage(status) {
			result.Result = "pending"
			result.Reason = "ipv6_stage_not_confirmed"
			return
		}
		e.intent.Operation = rawString(status["operation"])
	} else {
		// A completed commit may have lost its reply. Publication was already
		// confirmed before entering this phase, so recover forward only.
		if e.intent.Phase == "committing" && configHash(current) == e.intent.CandidateHash {
			if _, err = e.helper(ctx, configTransactionRequest{Action: "check-ipv6-live", Expected: current, ServerIPv6: e.intent.CIDR}); err == nil && e.save("complete") == nil {
				result.Result = "applied"
				result.Reason = "ipv6_commit_recovered"
				return
			}
		}
		result.Result = "recovery_required"
		result.Reason = "ipv6_stage_identity_changed"
		return
	}
	ownedStage = true
	if e.intent.PublicationAttempted {
		publication, err := e.feed(ctx, "ipv6-publication-status", request{Container: e.req.Container, Operation: e.intent.Publication})
		if err != nil {
			result.Result = "pending"
			result.Reason = "ipv6_publication_unknown"
			return
		}
		if rawBool(publication["current"]) {
			return e.commit(ctx)
		}
		// Only the IPv6 extension is republished against the CURRENT delivery
		// state. Preserve intervening endpoint/protocol updates, and never undo
		// an address that any signed client might already be using.
		currentState := rawString(info["stateTag"])
		if currentState != e.intent.ExpectedState {
			if !configOperationOK(currentState) {
				result.Result = "pending"
				return
			}
			e.intent.Publication, err = randomHex(32)
			if err != nil {
				return
			}
			e.intent.ExpectedState = currentState
			if e.save("publishing") != nil {
				return
			}
		}
	}
	if !e.intent.PublicationAttempted && e.save("staged") != nil {
		return
	}
	if _, err = e.helper(ctx, configTransactionRequest{Action: "apply", Operation: e.intent.Operation}); err != nil {
		result.Reason = "ipv6_apply_not_confirmed"
		return
	}
	if !e.intent.PublicationAttempted && e.save("applied") != nil {
		return
	}
	if _, err = e.helper(ctx, configTransactionRequest{Action: "verify-ipv6-egress", Operation: e.intent.Operation}); err != nil {
		result.Reason = "ipv6_egress_unverified"
		return
	}
	if e.req.ExpectedPublicKey != "" {
		// From this persisted boundary onwards an unknown response must NEVER
		// roll back IPv6: clients may already have fetched the signed revision.
		e.intent.PublicationAttempted = true
		if e.save("publishing") != nil {
			return
		}
		publication, err := e.feed(ctx, "publish-ipv6-if", request{Container: e.req.Container, Operation: e.intent.Publication, ExpectedState: e.intent.ExpectedState, ClientIPv6: e.intent.Assignments})
		if err != nil || !rawBool(publication["ok"]) {
			result.Result = "pending"
			result.Reason = "ipv6_publication_unknown"
			return
		}
		confirmed, err := e.feed(ctx, "ipv6-publication-status", request{Container: e.req.Container, Operation: e.intent.Publication})
		if err != nil || !rawBool(confirmed["current"]) {
			result.Result = "pending"
			result.Reason = "ipv6_publication_unknown"
			return
		}
	}
	return e.commit(ctx)
}

func (e *ipv6UpgradeEngine) commit(ctx context.Context) rolloutResult {
	result := rolloutResult{Version: 1, Result: "pending", Reason: "ipv6_commit_unknown"}
	if e.save("committing") != nil {
		return result
	}
	if _, err := e.helper(ctx, configTransactionRequest{Action: "commit", Operation: e.intent.Operation}); err != nil {
		return result
	}
	if e.save("complete") != nil {
		return result
	}
	result.Result = "applied"
	result.Reason = "ipv6_enabled"
	return result
}

func validIPv6UpgradeIntent(intent ipv6UpgradeIntent) bool {
	if intent.Request.ForwardingPrefix != "" && (len(intent.Request.ForwardingPrefix) != forwardingPrefixSize || configHash([]byte(intent.Request.ForwardingPrefix)) != forwardingPrefixHash) {
		return false
	}
	if (intent.StartupOriginalHash == "") != (intent.StartupCandidateHash == "") || (intent.StartupOriginalHash != "" && (!configOperationOK(intent.StartupOriginalHash) || !configOperationOK(intent.StartupCandidateHash))) || (intent.StartupOperation != "" && (!configOperationOK(intent.StartupOperation) || intent.StartupOriginalHash == "")) {
		return false
	}
	if intent.Version != 1 || !containerOK(intent.Request.Container) || !configOperationOK(intent.Target) || !configOperationOK(intent.OriginalHash) || !configOperationOK(intent.CandidateHash) || !configIPv6JournalOK(&configIPv6Journal{CIDR: intent.CIDR}) || intent.Assignments == nil || clientIPv6AssignmentsOK(intent.Assignments) != nil {
		return false
	}
	if (intent.Request.ExpectedPublicKey == "") != (intent.Request.ExpectedCertificate == "") {
		return false
	}
	if intent.Request.ExpectedPublicKey == "" {
		if intent.Publication != "" || intent.ExpectedState != "" || intent.PublicationAttempted {
			return false
		}
	} else if !configOperationOK(intent.Publication) || !configOperationOK(intent.ExpectedState) {
		return false
	}
	if intent.Operation != "" && !configOperationOK(intent.Operation) {
		return false
	}
	switch intent.Phase {
	case "prepared":
		return !intent.PublicationAttempted
	case "staged", "applied", "rolled_back":
		return configOperationOK(intent.Operation) && !intent.PublicationAttempted
	case "publishing":
		return configOperationOK(intent.Operation) && intent.PublicationAttempted
	case "committing", "complete":
		return configOperationOK(intent.Operation)
	default:
		return false
	}
}

func runIPv6Upgrade(ctx context.Context, req ipv6UpgradeRequest) rolloutResult {
	rejected := rolloutResult{Version: 1, Result: "rejected", Reason: "invalid_ipv6_upgrade_request"}
	if os.Geteuid() != 0 || !containerOK(req.Container) || (req.ExpectedPublicKey == "") != (req.ExpectedCertificate == "") {
		return rejected
	}
	dir := filepath.Join("/var/lib/amnezia/updates", "ipv6-"+req.Container)
	if os.MkdirAll(dir, 0700) != nil {
		return rejected
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return rejected
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		return rejected
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return rejected
	}
	lock, err := lockConfig(filepath.Join(dir, "intent"))
	if err != nil {
		return rejected
	}
	defer lock.Close()
	engine := ipv6UpgradeEngine{docker: realDocker, dir: dir, req: req}
	raw, info, err := readConfigFile(filepath.Join(dir, "intent.json"), 4<<20)
	if err == nil {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || owner.Nlink != 1 || info.Mode().Perm() != 0600 {
			return rejected
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&engine.intent) != nil || decoder.Decode(new(any)) != io.EOF || !validIPv6UpgradeIntent(engine.intent) {
			return rejected
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return rejected
	}
	return engine.execute(ctx)
}
