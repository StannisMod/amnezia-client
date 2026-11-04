package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const rolloutContainer = "amnezia-awg2"
const rolloutConfig = "/opt/amnezia/awg/awg0.conf"
const deliveryContainer = "amnezia-connection-updates"
const deliveryVolume = "amnezia-connection-updates-state"

type rolloutRequest struct {
	Host                string `json:"host"`
	AdminPublicKey      string `json:"adminPublicKey"`
	ExpectedPublicKey   string `json:"expectedPublicKey"`
	ExpectedCertificate string `json:"expectedCertificate"`
}
type rolloutResult struct {
	Version  int             `json:"version"`
	Result   string          `json:"result"`
	Reason   string          `json:"reason,omitempty"`
	Audit    string          `json:"audit,omitempty"`
	Settings json.RawMessage `json:"settings,omitempty"`
}
type dockerRunner func(context.Context, []string, []byte) ([]byte, error)

func realDocker(ctx context.Context, args []string, input []byte) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	if input != nil {
		command.Stdin = strings.NewReader(string(input))
	}
	return command.CombinedOutput()
}

type rolloutEngine struct {
	docker               dockerRunner
	work                 string
	targetID             string
	deliveryImage        string
	req                  rolloutRequest
	touched              bool
	publicationAttempted bool
	originalSaved        []byte
	originalLive         []byte
	oldSettings          json.RawMessage
}

func (e *rolloutEngine) call(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return e.docker(bounded, args, input)
}
func (e *rolloutEngine) inspect(ctx context.Context, name, format string) (string, error) {
	b, err := e.call(ctx, nil, "inspect", "-f", format, name)
	return strings.TrimSpace(string(b)), err
}
func (e *rolloutEngine) phase(name string) error {
	f, err := os.OpenFile(filepath.Join(e.work, "phase"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(name + "\n")
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}
func (e *rolloutEngine) feed(ctx context.Context, action string, req request) (map[string]json.RawMessage, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	out, err := e.call(ctx, raw, "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", "type=volume,source="+deliveryVolume+",target=/data", e.deliveryImage, action)
	if err != nil {
		return nil, errors.New("delivery command failed")
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(out, &result) != nil {
		return nil, errors.New("invalid delivery response")
	}
	if action == "publish" || action == "publish-if" || action == "publish-if-live" {
		var ok bool
		if json.Unmarshal(result["ok"], &ok) != nil || !ok {
			return nil, errors.New("publication not confirmed")
		}
	}
	return result, nil
}
func iniInterface(raw []byte) (map[string]string, []string, error) {
	fields := map[string]string{}
	peers := []string{}
	section := ""
	interfaces := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			if line == "[Interface]" {
				interfaces++
			}
			if line != "[Interface]" && line != "[Peer]" {
				return nil, nil, errors.New("unknown section")
			}
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			return nil, nil, errors.New("invalid configuration")
		}
		key, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if section == "[Interface]" {
			if _, exists := fields[key]; exists {
				return nil, nil, errors.New("duplicate interface setting")
			}
			fields[key] = value
		}
		if section == "[Peer]" && key == "PublicKey" {
			if !keyOK(value) {
				return nil, nil, errors.New("invalid peer identity")
			}
			peers = append(peers, value)
		}
	}
	if interfaces != 1 || !keyOK(fields["PrivateKey"]) {
		return nil, nil, errors.New("invalid interface identity")
	}
	return fields, peers, nil
}
func canonicalConfig(raw []byte) (string, error) {
	_, _, err := iniInterface(raw)
	if err != nil {
		return "", err
	}
	section := ""
	peer := ""
	group := []string{}
	result := []string{}
	flush := func() {
		for _, line := range group {
			result = append(result, peer+"|"+line)
		}
		group = nil
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			flush()
			section = line
			peer = ""
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			return "", errors.New("invalid configuration")
		}
		key, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if key == "Endpoint" || ((key == "RandomTrailers" || key == "DisableCookies") && value == "off") {
			continue
		}
		if value == "0" {
			switch key {
			case "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "FwMark", "PersistentKeepalive":
				continue
			}
		}
		if section == "[Peer]" && key == "PublicKey" {
			peer = value
		}
		group = append(group, key+"="+value)
	}
	flush()
	sort.Strings(result)
	return strings.Join(result, "\n"), nil
}
func patchProtection(raw []byte, key string, padding map[string]string) ([]byte, error) {
	if _, _, err := iniInterface(raw); err != nil {
		return nil, err
	}
	section := ""
	result := []string{}
	added := false
	appendFields := func() {
		if section != "[Interface]" || added {
			return
		}
		for _, name := range []string{"S1", "S2", "S3", "S4"} {
			result = append(result, name+" = "+padding[name])
		}
		result = append(result, "HeaderProtectionKey = "+key)
		added = true
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			appendFields()
			section = trimmed
			result = append(result, line)
			continue
		}
		name := strings.TrimSpace(strings.SplitN(trimmed, "=", 2)[0])
		if section == "[Interface]" && (name == "HeaderProtectionKey" || padding[name] != "") {
			continue
		}
		result = append(result, line)
	}
	appendFields()
	return []byte(strings.Join(result, "\n")), nil
}
func protectionPadding(fields map[string]string) (map[string]string, error) {
	result := map[string]string{}
	used := map[uint64]bool{}
	names := []string{"S1", "S2", "S3", "S4"}
	sizes := []uint64{148, 92, 64, 32}
	for index, name := range names {
		value := uint64(0)
		var err error
		if fields[name] != "" {
			value, err = strconv.ParseUint(fields[name], 10, 32)
			if err != nil {
				return nil, err
			}
		}
		if value < 12 {
			value = 12
		}
		for used[value+sizes[index]] {
			value++
		}
		if value+sizes[index] > 65535 {
			return nil, errors.New("padding exceeds UDP packet size")
		}
		used[value+sizes[index]] = true
		result[name] = strconv.FormatUint(value, 10)
	}
	return result, nil
}
func settingsFor(fields map[string]string, host, pub string) (json.RawMessage, error) {
	port, err := strconv.Atoi(fields["ListenPort"])
	if err != nil {
		return nil, err
	}
	values := map[string]any{"hostName": host, "port": port, "server_pub_key": pub}
	for _, name := range awgKeys {
		if value, exists := fields[name]; exists {
			values[name] = value
		}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	return raw, settingsOK(raw, rolloutContainer)
}
func (e *rolloutEngine) healthy(ctx context.Context) bool {
	for i := 0; i < 15; i++ {
		if _, err := e.call(ctx, nil, "exec", e.targetID, "awg", "show", "awg0"); err == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
	return false
}
func (e *rolloutEngine) restore(ctx context.Context) bool {
	if e.phase("rolling_back") != nil {
		return false
	}
	if err := os.WriteFile(filepath.Join(e.work, "restore.conf"), e.originalSaved, 0600); err != nil {
		return false
	}
	if _, err := e.call(ctx, nil, "cp", filepath.Join(e.work, "restore.conf"), e.targetID+":"+rolloutConfig); err != nil {
		return false
	}
	if _, err := e.call(ctx, nil, "restart", e.targetID); err != nil {
		return false
	}
	if !e.healthy(ctx) {
		return false
	}
	actual, err := e.call(ctx, nil, "exec", e.targetID, "awg", "showconf", "awg0")
	if err != nil {
		return false
	}
	expectedCanonical, err := canonicalConfig(e.originalLive)
	if err != nil {
		return false
	}
	actualCanonical, err := canonicalConfig(actual)
	if err != nil || expectedCanonical != actualCanonical {
		return false
	}
	if e.publicationAttempted {
		if _, err = e.feed(ctx, "publish", request{Container: rolloutContainer, Settings: e.oldSettings}); err != nil {
			return false
		}
	}
	return true
}
func (e *rolloutEngine) execute(ctx context.Context) (result rolloutResult) {
	result = rolloutResult{Version: 1, Result: "rejected", Reason: "preflight_failed", Audit: e.work}
	defer func() {
		if e.touched && result.Result != "applied" {
			recovery, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if e.restore(recovery) {
				result.Result = "rolled_back"
			} else {
				result.Result = "rollback_failed"
			}
			result.Settings = nil
		}
		// No secret values or raw subprocess output are written to diagnostic logs.
		raw, _ := json.Marshal(result)
		_ = os.WriteFile(filepath.Join(e.work, "result.json"), raw, 0600)
		_ = e.phase(result.Result)
	}()
	id, err := e.inspect(ctx, rolloutContainer, "{{.Id}}")
	if err != nil || id == "" {
		return
	}
	e.targetID = id
	running, err := e.inspect(ctx, id, "{{.State.Running}}")
	if err != nil || running != "true" {
		return
	}
	if _, err = e.call(ctx, nil, "exec", id, "test", "-e", "/sys/class/net/awg0/tun_flags"); err != nil {
		return
	}
	if _, err = e.call(ctx, nil, "exec", id, "sh", "-c", `strings /usr/bin/amneziawg-go | grep -q '^path[[:space:]]github[.]com/amnezia-vpn/amneziawg-go/v3$'`); err != nil {
		return
	}
	owner, err := e.inspect(ctx, deliveryContainer, `{{index .Config.Labels "org.amnezia.connection-updates"}}`)
	if err != nil || owner != "1" {
		return
	}
	e.deliveryImage, err = e.inspect(ctx, deliveryContainer, "{{.Image}}")
	if err != nil {
		return
	}
	info, err := e.feed(ctx, "info", request{})
	if err != nil {
		return
	}
	var signing, certificate string
	_ = json.Unmarshal(info["publicKey"], &signing)
	_ = json.Unmarshal(info["certificate"], &certificate)
	if signing != e.req.ExpectedPublicKey || certificate != e.req.ExpectedCertificate {
		result.Reason = "delivery_identity_changed"
		return
	}
	e.originalSaved, err = e.call(ctx, nil, "exec", id, "cat", rolloutConfig)
	if err != nil {
		return
	}
	e.originalLive, err = e.call(ctx, nil, "exec", id, "awg", "showconf", "awg0")
	if err != nil {
		return
	}
	fields, peers, err := iniInterface(e.originalLive)
	if err != nil {
		return
	}
	stripped, err := e.call(ctx, nil, "exec", id, "awg-quick", "strip", rolloutConfig)
	if err != nil {
		return
	}
	savedCanonical, err := canonicalConfig(stripped)
	if err != nil {
		return
	}
	liveCanonical, err := canonicalConfig(e.originalLive)
	if err != nil || savedCanonical != liveCanonical {
		result.Reason = "unsaved_runtime_changes"
		return
	}
	pubRaw, err := e.call(ctx, nil, "exec", id, "awg", "show", "awg0", "public-key")
	if err != nil {
		return
	}
	pub := strings.TrimSpace(string(pubRaw))
	if !keyOK(pub) {
		return
	}
	mode, inspectErr := e.inspect(ctx, id, "{{.HostConfig.NetworkMode}}")
	if inspectErr != nil || (mode != "default" && mode != "bridge") {
		result.Reason = "unsupported_layout"
		return
	}
	mountsJSON, inspectErr := e.inspect(ctx, id, "{{json .Mounts}}")
	var mounts []struct{ Destination string }
	if inspectErr != nil || json.Unmarshal([]byte(mountsJSON), &mounts) != nil {
		return
	}
	for _, mount := range mounts {
		if mount.Destination != "/lib/modules" {
			result.Reason = "unsupported_layout"
			return
		}
	}
	bindingsJSON, inspectErr := e.inspect(ctx, id, "{{json .HostConfig.PortBindings}}")
	var bindings map[string][]struct {
		HostIp   string
		HostPort string
	}
	if inspectErr != nil || json.Unmarshal([]byte(bindingsJSON), &bindings) != nil || len(bindings) != 1 {
		return
	}
	ports := bindings[fields["ListenPort"]+"/udp"]
	if len(ports) == 0 {
		return
	}
	for _, port := range ports {
		if port.HostPort != fields["ListenPort"] || (port.HostIp != "" && port.HostIp != "0.0.0.0" && port.HostIp != "::") {
			result.Reason = "unsupported_port_mapping"
			return
		}
	}
	e.oldSettings, err = settingsFor(fields, e.req.Host, pub)
	if err != nil {
		return
	}
	// A retry after a lost SSH result must synchronize the admin profile without
	// rotating an already-active key or disrupting users a second time.
	if current := fields["HeaderProtectionKey"]; current != "" && current != base64.StdEncoding.EncodeToString(make([]byte, 32)) {
		if !keyOK(current) {
			return
		}
		var tag string
		if json.Unmarshal(info["stateTag"], &tag) != nil {
			return
		}
		if _, err = e.feed(ctx, "publish-if-live", request{Container: rolloutContainer, Settings: e.oldSettings, ExpectedState: tag, ClientPublicKeys: peers}); err != nil {
			result.Reason = "publication_failed"
			return
		}
		result.Result = "applied"
		result.Reason = ""
		result.Settings = e.oldSettings
		return
	}
	clients := []string{}
	for _, peer := range peers {
		if peer != e.req.AdminPublicKey {
			clients = append(clients, peer)
		}
	}
	coverage, err := e.feed(ctx, "coverage", request{Container: rolloutContainer, ClientPublicKeys: clients})
	if err != nil {
		result.Reason = "delivery_service_upgrade_required"
		return
	}
	var missing int
	var expectedTag string
	if json.Unmarshal(coverage["missing"], &missing) != nil || json.Unmarshal(coverage["stateTag"], &expectedTag) != nil || missing != 0 {
		result.Reason = "clients_without_updates"
		return
	}
	readinessRaw, readinessError := e.call(ctx, mustJSON(request{Container: rolloutContainer, ClientPublicKeys: clients}), "exec", "-i", deliveryContainer, "/updates", "readiness")
	var ready map[string]json.RawMessage
	var notReady int
	if readinessError != nil || json.Unmarshal(readinessRaw, &ready) != nil || json.Unmarshal(ready["notReady"], &notReady) != nil {
		result.Reason = "delivery_service_upgrade_required"
		return
	}
	if notReady != 0 {
		result.Reason = "clients_not_ready"
		return
	}
	if json.Unmarshal(ready["stateTag"], &expectedTag) != nil {
		return
	}
	padding, err := protectionPadding(fields)
	if err != nil {
		return
	}
	key := fields["HeaderProtectionKey"]
	if key == "" || key == base64.StdEncoding.EncodeToString(make([]byte, 32)) {
		bytes := make([]byte, 32)
		if _, err = rand.Read(bytes); err != nil {
			return
		}
		key = base64.StdEncoding.EncodeToString(bytes)
	}
	if !keyOK(key) {
		return
	}
	newSaved, err := patchProtection(e.originalSaved, key, padding)
	if err != nil {
		return
	}
	expected, err := patchProtection(e.originalLive, key, padding)
	if err != nil {
		return
	}
	wanted, _, err := iniInterface(expected)
	if err != nil {
		return
	}
	newSettings, err := settingsFor(wanted, e.req.Host, pub)
	if err != nil {
		return
	}
	for name, data := range map[string][]byte{"before.saved.conf": e.originalSaved, "before.live.conf": e.originalLive, "candidate.conf": newSaved} {
		if os.WriteFile(filepath.Join(e.work, name), data, 0600) != nil {
			return
		}
	}
	if e.phase("prepared") != nil {
		return
	}
	currentSaved, currentError := e.call(ctx, nil, "exec", id, "cat", rolloutConfig)
	if currentError != nil || !bytes.Equal(currentSaved, e.originalSaved) {
		result.Reason = "configuration_changed"
		return
	}
	currentLive, currentError := e.call(ctx, nil, "exec", id, "awg", "showconf", "awg0")
	if currentError != nil {
		return
	}
	currentCanonical, currentError := canonicalConfig(currentLive)
	if currentError != nil || currentCanonical != liveCanonical {
		result.Reason = "configuration_changed"
		return
	}
	// Set before the first mutation so all ordinary failures and signals restore.
	e.touched = true
	result.Reason = "activation_failed"
	if _, err = e.call(ctx, nil, "cp", filepath.Join(e.work, "candidate.conf"), id+":"+rolloutConfig); err != nil {
		return
	}
	if _, err = e.call(ctx, nil, "restart", id); err != nil {
		return
	}
	if !e.healthy(ctx) {
		return
	}
	actual, err := e.call(ctx, nil, "exec", id, "awg", "showconf", "awg0")
	if err != nil {
		return
	}
	actualCanonical, err := canonicalConfig(actual)
	if err != nil {
		return
	}
	wantedCanonical, err := canonicalConfig(expected)
	if err != nil || actualCanonical != wantedCanonical {
		return
	}
	if e.phase("server_active") != nil {
		return
	}
	e.publicationAttempted = true
	if _, err = e.feed(ctx, "publish-if-live", request{Container: rolloutContainer, Settings: newSettings, ExpectedState: expectedTag, ClientPublicKeys: peers}); err != nil {
		result.Reason = "publication_failed"
		return
	}
	if e.phase("published") != nil {
		return
	}
	result.Result = "applied"
	result.Reason = ""
	result.Settings = newSettings
	return
}
func runRollout(ctx context.Context, req rolloutRequest) rolloutResult {
	rejected := rolloutResult{Version: 1, Result: "rejected", Reason: "invalid_request"}
	if os.Geteuid() != 0 || req.Host == "" || req.ExpectedPublicKey == "" || req.ExpectedCertificate == "" || (req.AdminPublicKey != "" && !keyOK(req.AdminPublicKey)) {
		return rejected
	}
	root := "/var/lib/amnezia/updates"
	if os.MkdirAll(root, 0700) != nil || os.Chmod(root, 0700) != nil {
		return rejected
	}
	lock, err := os.OpenFile(filepath.Join(root, rolloutContainer+".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return rejected
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		rejected.Reason = "busy"
		return rejected
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	id, err := randomHex(16)
	if err != nil {
		return rejected
	}
	work := filepath.Join(root, "awg3-protection-"+id)
	if os.Mkdir(work, 0700) != nil {
		return rejected
	}
	engine := rolloutEngine{docker: realDocker, work: work, req: req}
	return engine.execute(ctx)
}
func decodeRolloutRequest(raw []byte) (rolloutRequest, error) {
	var req rolloutRequest
	if len(raw) > 65536 || json.Unmarshal(raw, &req) != nil {
		return req, fmt.Errorf("invalid rollout request")
	}
	return req, nil
}

func mustJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }
