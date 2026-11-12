package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unicode/utf8"
)

var errConfigConflict = errors.New("configuration changed during transaction")

type configIPv6Journal struct {
	CIDR       string `json:"cidr"`
	WasPresent bool   `json:"wasPresent"`
	AddIntent  bool   `json:"addIntent"`
	Ambiguous  bool   `json:"ambiguous"`
	Applied    bool   `json:"applied"`
}
type configJournal struct {
	Version           int                `json:"version"`
	Operation         string             `json:"operation"`
	IPv6              *configIPv6Journal `json:"ipv6,omitempty"`
	NativeOriginal    []byte             `json:"nativeOriginal,omitempty"`
	NativeHash        string             `json:"nativeHash,omitempty"`
	NativeWriteIntent bool               `json:"nativeWriteIntent"`
	NativeApplied     bool               `json:"nativeApplied"`
	Original          []byte             `json:"original"`
	OriginalHash      string             `json:"originalHash"`
	CandidateHash     string             `json:"candidateHash"`
	Mode              uint32             `json:"mode"`
	UID               int                `json:"uid"`
	GID               int                `json:"gid"`
}
type configTransaction struct {
	path    string
	lock    *os.File
	journal configJournal
}

func configHash(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// All participating writers must hold the same sidecar lock. This is not a
// compare-and-swap against arbitrary legacy writers which ignore that lock.
func lockConfig(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid configuration path")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || parent != filepath.Dir(path) {
		return nil, errors.New("symlink configuration directory")
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || parentInfo.Mode().Perm()&0022 != 0 {
		return nil, errors.New("writable configuration directory")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || int(parentStat.Uid) != os.Geteuid() {
		return nil, errors.New("foreign configuration directory")
	}
	file, err := os.OpenFile(path+".amnezia-lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("invalid configuration lock")
	}
	lockStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || lockStat.Nlink != 1 || int(lockStat.Uid) != os.Geteuid() || info.Mode().Perm() != 0600 {
		file.Close()
		return nil, errors.New("foreign configuration lock")
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
func syncConfigDirectory(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func readConfigFile(path string, limit int64) ([]byte, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, nil, errors.New("invalid configuration file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, nil, errors.New("configuration read failed")
	}
	return data, info, nil
}
func writeConfigAtomic(path string, data []byte, mode os.FileMode, uid, gid int, exclusive bool) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".amnezia-config-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chown(uid, gid); err == nil {
		err = file.Chmod(mode.Perm())
	}
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeError := file.Close()
	if err == nil {
		err = closeError
	}
	if err != nil {
		return err
	}
	if exclusive {
		err = os.Link(name, path)
	} else {
		err = os.Rename(name, path)
	}
	if err != nil {
		return err
	}
	return syncConfigDirectory(path)
}
func beginConfigTransaction(path string, expected, candidate []byte) (*configTransaction, error) {
	return beginPreparedConfigTransaction(path, expected, candidate, nil)
}
func beginPreparedConfigTransaction(path string, expected, candidate []byte, prepare func(*configJournal) error) (*configTransaction, error) {
	if len(expected) > 4<<20 || len(candidate) > 4<<20 || len(candidate) == 0 {
		return nil, errors.New("invalid configuration size")
	}
	lock, err := lockConfig(path)
	if err != nil {
		return nil, err
	}
	accepted := false
	defer func() {
		if !accepted {
			lock.Close()
		}
	}()
	original, info, err := readConfigFile(path, 4<<20)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(original, expected) {
		return nil, errConfigConflict
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || info.Mode().Perm()&0022 != 0 || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("linked configuration file")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	journal := configJournal{Version: 5, Operation: hex.EncodeToString(nonce), Original: original, OriginalHash: configHash(original), CandidateHash: configHash(candidate), Mode: uint32(info.Mode().Perm()), UID: int(stat.Uid), GID: int(stat.Gid)}
	if prepare != nil {
		if err := prepare(&journal); err != nil {
			return nil, err
		}
	}
	if !configNativeJournalOK(journal) || !configIPv6JournalOK(journal.IPv6) || !configIPv6PlanMatches(journal) {
		return nil, errors.New("invalid IPv6 journal plan")
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return nil, err
	}
	if err = writeConfigAtomic(path+".amnezia-journal", raw, 0600, journal.UID, journal.GID, true); err != nil {
		return nil, err
	}
	// Keep the journal on any later error, including uncertain rename/fsync outcome.
	if err = writeConfigAtomic(path, candidate, info.Mode(), journal.UID, journal.GID, false); err != nil {
		return nil, err
	}
	accepted = true
	return &configTransaction{path, lock, journal}, nil
}
func resumeConfigTransaction(path string) (*configTransaction, error) {
	lock, err := lockConfig(path)
	if err != nil {
		return nil, err
	}
	accepted := false
	defer func() {
		if !accepted {
			lock.Close()
		}
	}()
	raw, info, err := readConfigFile(path+".amnezia-journal", 12<<20)
	if err != nil {
		return nil, err
	}
	var journal configJournal
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || decoder.Decode(new(any)) != io.EOF || journal.Version != 5 || !configNativeJournalOK(journal) || !configIPv6JournalOK(journal.IPv6) || !configIPv6PlanMatches(journal) || !configOperationOK(journal.Operation) || len(journal.Original) > 4<<20 || journal.OriginalHash != configHash(journal.Original) || len(journal.CandidateHash) != 64 || journal.Mode & ^uint32(0777) != 0 || info.Mode().Perm() != 0600 || journal.UID < 0 || journal.GID < 0 {
		return nil, errors.New("invalid configuration journal")
	}
	hash, err := hex.DecodeString(journal.CandidateHash)
	if err != nil || hex.EncodeToString(hash) != journal.CandidateHash {
		return nil, errors.New("invalid candidate digest")
	}
	accepted = true
	return &configTransaction{path, lock, journal}, nil
}
func (transaction *configTransaction) close() {
	if transaction.lock != nil {
		transaction.lock.Close()
		transaction.lock = nil
	}
}
func (transaction *configTransaction) finish(rollback bool) error {
	if transaction.lock == nil {
		return errors.New("closed configuration transaction")
	}
	defer transaction.close()
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
		if err = writeConfigAtomic(transaction.path, transaction.journal.Original, os.FileMode(transaction.journal.Mode), transaction.journal.UID, transaction.journal.GID, false); err != nil {
			return err
		}
	}
	if err = os.Remove(transaction.path + ".amnezia-journal"); err != nil {
		return err
	}
	return syncConfigDirectory(transaction.path)
}

func configOperationOK(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

type configTransactionRequest struct {
	Action     string `json:"action"`
	Container  string `json:"container"`
	Operation  string `json:"operation,omitempty"`
	Expected   []byte `json:"expected,omitempty"`
	Candidate  []byte `json:"candidate,omitempty"`
	ServerIPv6 string `json:"serverIpv6,omitempty"`
}

// Only the root-owned helper command invokes this; no HTTP handler exposes it.
func configTransactionCommand(input io.Reader, output io.Writer, paths map[string]string) error {
	raw, err := io.ReadAll(io.LimitReader(input, (12<<20)+1))
	if err != nil || len(raw) > 12<<20 {
		return errors.New("invalid configuration transaction request")
	}
	var request configTransactionRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid configuration transaction request")
	}
	path, exists := paths[request.Container]
	if !exists {
		return errors.New("unsupported configuration container")
	}
	if request.Action == "capabilities" {
		if request.Operation != "" || len(request.Expected) != 0 || len(request.Candidate) != 0 || request.ServerIPv6 != "" {
			return errors.New("unexpected capability fields")
		}
		return json.NewEncoder(output).Encode(map[string]any{"version": 1, "features": []string{"native-mutation-v1"}})
	}
	if request.Action == "check-live" {
		if request.Operation != "" || len(request.Expected) == 0 || len(request.Expected) > 4<<20 || len(request.Candidate) != 0 || request.ServerIPv6 != "" {
			return errors.New("invalid live-state check")
		}
		lock, err := lockConfig(path)
		if err != nil {
			return err
		}
		defer lock.Close()
		if _, err := os.Lstat(path + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("configuration transaction is pending")
		}
		current, info, err := readConfigFile(path, 4<<20)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 || !bytes.Equal(current, request.Expected) {
			return errConfigConflict
		}
		native, err := captureNativeProtocol(request.Container)
		if err != nil {
			return err
		}
		if err := verifyNativeConfigBaseline(request.Container, path, native); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"version": 1, "current": true, "candidateHash": configHash(current)})
	}
	var transaction *configTransaction
	var assignments map[string]string
	if request.Action == "stage-ipv6" {
		if request.Operation != "" || len(request.Candidate) != 0 {
			return errors.New("unexpected IPv6 stage fields")
		}
		plan, planError := planIPv6Config(request.Expected, request.ServerIPv6)
		if planError != nil {
			return planError
		}
		assignments = plan.Assignments
		transaction, err = beginPreparedConfigTransaction(path, request.Expected, plan.Config, func(journal *configJournal) error {
			present, err := protocolIPv6Present(request.Container, request.ServerIPv6)
			if err != nil {
				return err
			}
			native, err := captureNativeProtocol(request.Container)
			if err != nil {
				return err
			}
			if err := verifyNativeConfigBaseline(request.Container, path, native); err != nil {
				return err
			}
			journal.NativeOriginal = native
			journal.NativeHash = configHash(native)
			journal.IPv6 = &configIPv6Journal{CIDR: request.ServerIPv6, WasPresent: present}
			return nil
		})
	} else if request.Action == "stage" || request.Action == "stage-live" {
		if request.ServerIPv6 != "" {
			return errors.New("unexpected IPv6 stage field")
		}
		if request.Operation != "" {
			return errors.New("unexpected operation identifier")
		}
		if request.Action == "stage-live" {
			if !sameQuickSettings(request.Expected, request.Candidate) {
				return errors.New("live protocol mutation cannot change quick-only settings")
			}
			transaction, err = beginPreparedConfigTransaction(path, request.Expected, request.Candidate, func(journal *configJournal) error {
				native, err := captureNativeProtocol(request.Container)
				if err != nil {
					return err
				}
				if err := verifyNativeConfigBaseline(request.Container, path, native); err != nil {
					return err
				}
				journal.NativeOriginal = native
				journal.NativeHash = configHash(native)
				return nil
			})
		} else {
			transaction, err = beginConfigTransaction(path, request.Expected, request.Candidate)
		}
	} else {
		if len(request.Expected) != 0 || len(request.Candidate) != 0 || request.ServerIPv6 != "" {
			return errors.New("unexpected configuration data")
		}
		switch request.Action {
		case "status":
			if request.Operation != "" {
				return errors.New("unexpected operation identifier")
			}
		case "commit", "rollback", "apply", "apply-commit", "rollback-live", "prepare-forwarding":
			if !configOperationOK(request.Operation) {
				return errors.New("invalid operation identifier")
			}
		default:
			return errors.New("unsupported configuration transaction action")
		}
		transaction, err = resumeConfigTransaction(path)
	}
	if err != nil {
		return err
	}
	defer transaction.close()
	if request.Action != "stage" && request.Action != "stage-live" && request.Action != "stage-ipv6" && request.Action != "status" && request.Operation != transaction.journal.Operation {
		return errors.New("configuration operation mismatch")
	}
	result := map[string]any{"nativeWriteIntent": transaction.journal.NativeWriteIntent, "nativeApplied": transaction.journal.NativeApplied, "version": 1, "operation": transaction.journal.Operation, "originalHash": transaction.journal.OriginalHash, "candidateHash": transaction.journal.CandidateHash}
	if assignments != nil {
		result["clientIpv6"] = assignments
	}

	switch request.Action {
	case "prepare-forwarding":
		if err := prepareConfigForwarding(transaction, request.Container); err != nil {
			return err
		}
		result["ipv6ForwardingPrepared"] = true
	case "apply", "apply-commit", "rollback-live":
		if request.Action != "apply-commit" || !transaction.journal.NativeApplied {
			if err := applyConfigTransactionRuntime(transaction, request.Container, request.Action == "rollback-live"); err != nil {
				return err
			}
		}
		if request.Action == "apply-commit" {
			if err := verifyProtocolCommit(transaction, request.Container); err != nil {
				return err
			}
			if err := verifyIPv6Commit(transaction, request.Container); err != nil {
				return err
			}
			if err := transaction.finish(false); err != nil {
				return err
			}
		}
	case "commit", "rollback":
		if request.Action == "commit" {
			if err := verifyProtocolCommit(transaction, request.Container); err != nil {
				return err
			}
		}
		if len(transaction.journal.NativeOriginal) != 0 {
			if request.Action == "rollback" {
				return errors.New("native snapshot requires live rollback")
			}
			if !transaction.journal.NativeApplied {
				return errors.New("native configuration has not been applied")
			}
		}
		if transaction.journal.IPv6 != nil {
			if request.Action == "rollback" {
				return errors.New("IPv6 configuration requires live rollback")
			}
			if err := verifyIPv6Commit(transaction, request.Container); err != nil {
				return err
			}
		}
		if err := transaction.finish(request.Action == "rollback"); err != nil {
			return err
		}
	case "status":
		current, _, err := readConfigFile(path, 4<<20)
		if err != nil {
			return err
		}
		hash := configHash(current)
		state := "conflict"
		if hash == transaction.journal.OriginalHash {
			state = "original"
		} else if hash == transaction.journal.CandidateHash {
			state = "candidate"
		}
		result["state"] = state
	}
	if transaction.journal.IPv6 != nil {
		meta := transaction.journal.IPv6
		result["serverIpv6"] = meta.CIDR
		result["ipv6AddressPreexisting"] = meta.WasPresent
		result["ipv6Applied"] = meta.Applied
		result["ipv6AddressAmbiguous"] = meta.Ambiguous
		plan, err := planIPv6Config(transaction.journal.Original, meta.CIDR)
		if err != nil {
			return err
		}
		result["clientIpv6"] = plan.Assignments
	}
	result["nativeApplied"] = transaction.journal.NativeApplied
	result["nativeWriteIntent"] = transaction.journal.NativeWriteIntent
	return json.NewEncoder(output).Encode(result)
}

func (transaction *configTransaction) saveJournal() error {
	raw, err := json.Marshal(transaction.journal)
	if err != nil {
		return err
	}
	return writeConfigAtomic(transaction.path+".amnezia-journal", raw, 0600, transaction.journal.UID, transaction.journal.GID, false)
}

func configNativeJournalOK(journal configJournal) bool {
	if len(journal.NativeOriginal) == 0 {
		return journal.NativeHash == "" && !journal.NativeApplied && !journal.NativeWriteIntent && journal.IPv6 == nil
	}
	if journal.NativeApplied && !journal.NativeWriteIntent {
		return false
	}
	if journal.IPv6 != nil && journal.NativeApplied != journal.IPv6.Applied {
		return false
	}
	return len(journal.NativeOriginal) <= 4<<20 && utf8.Valid(journal.NativeOriginal) && journal.NativeHash == configHash(journal.NativeOriginal)
}

// installConfigHelper is called by a verified candidate executable, not by the
// currently installed helper. expectedHash must come from the owned deployment
// record; observing an arbitrary existing file does not establish ownership.
func installConfigHelper(configPath, startupPath, target string, candidate []byte, expectedHash string) error {
	if len(candidate) == 0 || len(candidate) > 64<<20 || (expectedHash != "" && !configOperationOK(expectedHash)) {
		return errors.New("invalid helper installation")
	}
	locks := []*os.File{}
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Close()
		}
	}()
	for _, path := range []string{target, configPath, startupPath} {
		lock, err := lockConfig(path)
		if err != nil {
			return err
		}
		locks = append(locks, lock)
	}
	for _, path := range []string{configPath, startupPath} {
		if _, err := os.Lstat(path + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("pending transaction prevents helper replacement")
		}
	}
	current, info, err := readConfigFile(target, 64<<20)
	if errors.Is(err, os.ErrNotExist) {
		if expectedHash != "" {
			return errConfigConflict
		}
		// Exclusive publication preserves a target created by an independent writer.
		return writeConfigAtomic(target, candidate, 0700, os.Geteuid(), os.Getegid(), true)
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe existing helper")
	}
	// An exact retry after a lost success response is harmless. No write occurs.
	if bytes.Equal(current, candidate) && info.Mode().Perm() == 0700 {
		return nil
	}
	if expectedHash == "" || configHash(current) != expectedHash {
		return errConfigConflict
	}
	return writeConfigAtomic(target, candidate, 0700, int(stat.Uid), int(stat.Gid), false)
}
