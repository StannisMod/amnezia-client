package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"
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
	NativeRollbackHash string             `json:"nativeRollbackHash,omitempty"`
	Version            int                `json:"version"`
	Operation          string             `json:"operation"`
	IPv6               *configIPv6Journal `json:"ipv6,omitempty"`
	NativeOriginal     []byte             `json:"nativeOriginal,omitempty"`
	NativeHash         string             `json:"nativeHash,omitempty"`
	NativeWriteIntent  bool               `json:"nativeWriteIntent"`
	NativeApplied      bool               `json:"nativeApplied"`
	Original           []byte             `json:"original"`
	OriginalHash       string             `json:"originalHash"`
	CandidateHash      string             `json:"candidateHash"`
	Mode               uint32             `json:"mode"`
	UID                int                `json:"uid"`
	GID                int                `json:"gid"`
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
		err = renameConfigNoReplace(name, path)
	} else {
		err = os.Rename(name, path)
	}
	if err != nil {
		return err
	}
	return syncConfigDirectory(path)
}

// Linux renameat2(RENAME_NOREPLACE) publishes the completed inode without the
// crash window in link(temp,target)+unlink(temp). Do not fall back to that
// two-step operation on an unsupported kernel/filesystem.
func renameConfigNoReplace(source, target string) error {
	if runtime.GOOS != "linux" {
		return syscall.ENOSYS
	}
	// Stable Linux UAPI numbers, checked against x/sys/unix zsysnum_linux files.
	// Keep the standalone server helper free of a new network-fetched dependency.
	var trap uintptr
	switch runtime.GOARCH {
	case "amd64":
		trap = 316
	case "386":
		trap = 353
	case "arm":
		trap = 382
	case "arm64", "loong64", "riscv64":
		trap = 276
	case "mips", "mipsle":
		trap = 4351
	case "mips64", "mips64le":
		trap = 5311
	case "ppc64", "ppc64le":
		trap = 357
	case "s390x":
		trap = 347
	default:
		return syscall.ENOSYS
	}
	old, err := syscall.BytePtrFromString(source)
	if err != nil {
		return err
	}
	next, err := syscall.BytePtrFromString(target)
	if err != nil {
		return err
	}
	currentDirectory := -100 // AT_FDCWD; paths used by the helper are absolute.
	_, _, errno := syscall.Syscall6(trap, uintptr(currentDirectory), uintptr(unsafe.Pointer(old)), uintptr(currentDirectory), uintptr(unsafe.Pointer(next)), 1, 0)
	runtime.KeepAlive(old)
	runtime.KeepAlive(next)
	if errno != 0 {
		return errno
	}
	return nil
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
	if _, err := readConfigReceipts(path); err != nil {
		return nil, err
	}
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
	journal := configJournal{Version: 6, Operation: hex.EncodeToString(nonce), Original: original, OriginalHash: configHash(original), CandidateHash: configHash(candidate), Mode: uint32(info.Mode().Perm()), UID: int(stat.Uid), GID: int(stat.Gid)}
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
	if _, err := readConfigReceipts(path); err != nil {
		return nil, err
	}
	journal, err := readLockedConfigJournal(path)
	if err != nil {
		return nil, err
	}

	accepted = true
	return &configTransaction{path, lock, journal}, nil
}

// Caller holds the matching configuration lock. Reading never changes a pending
// operation, which lets a candidate helper prove format compatibility first.
func readLockedConfigJournal(path string) (configJournal, error) {
	raw, info, err := readConfigFile(path+".amnezia-journal", 12<<20)
	if err != nil {
		return configJournal{}, err
	}
	var journal configJournal
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || decoder.Decode(new(any)) != io.EOF || (journal.Version != 5 && journal.Version != 6) || !configNativeJournalOK(journal) || !configIPv6JournalOK(journal.IPv6) || !configIPv6PlanMatches(journal) || !configOperationOK(journal.Operation) || len(journal.Original) > 4<<20 || journal.OriginalHash != configHash(journal.Original) || len(journal.CandidateHash) != 64 || journal.Mode & ^uint32(0777) != 0 || info.Mode().Perm() != 0600 || journal.UID < 0 || journal.GID < 0 {
		return configJournal{}, errors.New("invalid configuration journal")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || int(stat.Uid) != journal.UID || int(stat.Gid) != journal.GID {
		return configJournal{}, errors.New("foreign configuration journal")
	}
	hash, err := hex.DecodeString(journal.CandidateHash)
	if err != nil || hex.EncodeToString(hash) != journal.CandidateHash {
		return configJournal{}, errors.New("invalid candidate digest")
	}
	return journal, nil
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
	if err := transaction.completeReceipts(rollback); err != nil {
		return err
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
		return json.NewEncoder(output).Encode(map[string]any{"version": 1, "features": []string{"native-mutation-v1", "native-reconcile-v1", "native-rollback-guard-v1", "native-stage-restart-v1", "client-table-cas-v1", "native-receipt-v1", "client-table-migration-v1"}})
	}
	if request.Action == "prepare-receipt" || request.Action == "receipt-status" || request.Action == "check-revoked-peer" || request.Action == "ack-receipt" {
		return configReceiptCommand(path, request, output)
	}
	if request.Action == "replace-client-table" || request.Action == "check-client-table" || request.Action == "migrate-client-table" {
		return clientTableTransaction(path, request, output)
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
		case "commit", "rollback", "apply", "apply-commit", "rollback-live", "prepare-forwarding", "discard-stage":
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
	case "discard-stage":
		if len(transaction.journal.NativeOriginal) == 0 || transaction.journal.IPv6 != nil || transaction.journal.NativeWriteIntent || transaction.journal.NativeApplied || transaction.journal.NativeRollbackHash != "" {
			return errors.New("stage cannot be discarded")
		}
		current, _, err := readConfigFile(path, 4<<20)
		if err != nil {
			return err
		}
		if configHash(current) != transaction.journal.OriginalHash {
			return errConfigConflict
		}
		if err := transaction.finish(true); err != nil {
			return err
		}
		result["discardedStage"] = true
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
	result["rollbackPending"] = transaction.journal.NativeRollbackHash != "" && transaction.lock != nil
	result["nativeWriteIntent"] = transaction.journal.NativeWriteIntent
	return json.NewEncoder(output).Encode(result)
}

func (transaction *configTransaction) saveJournal() error {
	transaction.journal.Version = 6
	raw, err := json.Marshal(transaction.journal)
	if err != nil {
		return err
	}
	return writeConfigAtomic(transaction.path+".amnezia-journal", raw, 0600, transaction.journal.UID, transaction.journal.GID, false)
}

func configNativeJournalOK(journal configJournal) bool {
	if len(journal.NativeOriginal) == 0 {
		return journal.NativeRollbackHash == "" && journal.NativeHash == "" && !journal.NativeApplied && !journal.NativeWriteIntent && journal.IPv6 == nil
	}
	if journal.NativeRollbackHash != "" && (journal.Version != 6 || !configOperationOK(journal.NativeRollbackHash)) {
		return false
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
	return installConfigHelperCompatible(configPath, startupPath, target, candidate, expectedHash, false)
}

func installConfigHelperCompatible(configPath, startupPath, target string, candidate []byte, expectedHash string, ownedRecovery bool) error {
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
		if _, err := readConfigReceipts(path); err != nil {
			return err
		}
		if _, err := os.Lstat(path + ".amnezia-journal"); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if !ownedRecovery {
			return errors.New("unowned pending transaction prevents helper replacement")
		}
		journal, err := readLockedConfigJournal(path)
		if err != nil {
			return err
		}
		if path == startupPath && (len(journal.NativeOriginal) != 0 || journal.IPv6 != nil) {
			return errors.New("unsupported startup journal")
		}
		data, info, err := readConfigFile(path, 4<<20)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		hash := configHash(data)
		if !ok || stat.Nlink != 1 || int(stat.Uid) != journal.UID || int(stat.Gid) != journal.GID || uint32(info.Mode().Perm()) != journal.Mode || (hash != journal.OriginalHash && hash != journal.CandidateHash) {
			return errConfigConflict
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

// The receipt is written before publication, so a lost process/SSH session can
// reconcile either side of the atomic rename without trusting an unknown file.
func installOwnedConfigHelper(configPath, startupPath, target string, candidate []byte) error {
	if len(candidate) == 0 || len(candidate) > 64<<20 {
		return errors.New("invalid helper candidate")
	}
	lock, err := lockConfig(target + ".owner")
	if err != nil {
		return err
	}
	defer lock.Close()
	receiptPath := target + ".amnezia-owner"
	type receipt struct {
		Version   int    `json:"version"`
		Installed string `json:"installed"`
		Candidate string `json:"candidate"`
	}
	var state receipt
	raw, info, err := readConfigFile(receiptPath, 4096)
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || info.Mode().Perm() != 0600 {
			return errors.New("unsafe helper ownership receipt")
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF || state.Version != 1 || (state.Installed != "" && !configOperationOK(state.Installed)) || !configOperationOK(state.Candidate) {
			return errors.New("invalid helper ownership receipt")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	current, _, readErr := readConfigFile(target, 64<<20)
	expected := ""
	if readErr == nil {
		expected = configHash(current)
		if state.Version != 1 || (expected != state.Installed && expected != state.Candidate) {
			return errors.New("unowned helper executable")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	// A staged first-install receipt alone is not ownership of a journal that
	// appeared independently. Require prior completed installation or the
	// actual previously published candidate executable.
	ownedRecovery := readErr == nil || state.Installed != ""
	installed := expected
	if errors.Is(readErr, os.ErrNotExist) {
		installed = state.Installed
	}
	state = receipt{Version: 1, Installed: installed, Candidate: configHash(candidate)}
	pending, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := writeConfigAtomic(receiptPath, pending, 0600, os.Geteuid(), os.Getegid(), false); err != nil {
		return err
	}
	if err := installConfigHelperCompatible(configPath, startupPath, target, candidate, expected, ownedRecovery); err != nil {
		return err
	}
	state.Installed = state.Candidate
	complete, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeConfigAtomic(receiptPath, complete, 0600, os.Geteuid(), os.Getegid(), false)
}

// Client metadata shares the protocol lock so participating writers cannot
// replace a table from a stale snapshot or mutate it during a pending peer edit.
// This is a separate durable step; it does not claim atomicity with native state.
func clientTableTransaction(configPath string, request configTransactionRequest, output io.Writer) error {
	migration := request.Action == "migrate-client-table"
	if request.Operation != "" || request.ServerIPv6 != "" || !(validClientTable(request.Expected) || migration && validLegacyClientTable(request.Expected)) {
		return errors.New("invalid client table request")
	}
	if request.Action == "replace-client-table" || migration {
		if !validClientTable(request.Candidate) {
			return errors.New("invalid replacement client table")
		}
	} else if len(request.Candidate) != 0 {
		return errors.New("unexpected replacement client table")
	}
	lock, err := lockConfig(configPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := readConfigReceipts(configPath); err != nil {
		return err
	}
	if _, err := os.Lstat(configPath + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("configuration transaction is pending")
	}
	path := filepath.Join(filepath.Dir(configPath), "clientsTable")
	current, info, err := readConfigFile(path, 4<<20)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 || !(validClientTable(current) || migration && validLegacyClientTable(current)) {
		return errors.New("unsafe client table")
	}
	if !bytes.Equal(current, request.Expected) {
		return errConfigConflict
	}
	if migration && !clientTableMigrationPreserves(current, request.Candidate) {
		return errors.New("legacy client metadata would be lost")
	}
	result := current
	if (request.Action == "replace-client-table" || migration) && !bytes.Equal(current, request.Candidate) {
		if err := writeConfigAtomic(path, request.Candidate, info.Mode(), int(stat.Uid), int(stat.Gid), false); err != nil {
			return err
		}
		result = request.Candidate
	}
	return json.NewEncoder(output).Encode(map[string]any{"version": 1, "current": true, "candidateHash": configHash(result)})
}
func validClientTable(data []byte) bool {
	if len(data) == 0 || len(data) > 4<<20 || !utf8.Valid(data) {
		return false
	}
	var entries []json.RawMessage
	if json.Unmarshal(data, &entries) != nil || entries == nil {
		return false
	}
	for _, entry := range entries {
		var object map[string]json.RawMessage
		if json.Unmarshal(entry, &object) != nil || object == nil {
			return false
		}
	}
	return true
}

// Receipts are opt-in intents published before a live mutation. Completion is
// durable before journal removal. Unacknowledged records are never evicted;
// capacity exhaustion refuses new intents before any native/config change.
type configReceipt struct {
	OriginalHash    string `json:"originalHash"`
	CandidateHash   string `json:"candidateHash"`
	State           string `json:"state"`
	NativeOperation string `json:"nativeOperation,omitempty"`
}
type configReceipts struct {
	Version int                      `json:"version"`
	Records map[string]configReceipt `json:"records"`
}

const maxConfigReceipts = 256

func readConfigReceipts(path string) (configReceipts, error) {
	empty := configReceipts{Version: 1, Records: map[string]configReceipt{}}
	raw, info, err := readConfigFile(path+".amnezia-receipts", 2<<20)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || info.Mode().Perm() != 0600 {
		return empty, errors.New("unsafe configuration receipts")
	}
	var receipts configReceipts
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipts) != nil || decoder.Decode(new(any)) != io.EOF || receipts.Version != 1 || receipts.Records == nil || len(receipts.Records) > maxConfigReceipts {
		return empty, errors.New("invalid configuration receipts")
	}
	for id, record := range receipts.Records {
		if !configOperationOK(id) || !configOperationOK(record.OriginalHash) || !configOperationOK(record.CandidateHash) {
			return empty, errors.New("invalid receipt identity")
		}
		switch record.State {
		case "pending":
			if record.NativeOperation != "" {
				return empty, errors.New("invalid pending receipt")
			}
		case "committed", "rolled-back":
			if !configOperationOK(record.NativeOperation) {
				return empty, errors.New("invalid terminal receipt")
			}
		default:
			return empty, errors.New("unknown receipt outcome")
		}
	}
	return receipts, nil
}
func writeConfigReceipts(path string, receipts configReceipts) error {
	raw, err := json.Marshal(receipts)
	if err != nil {
		return err
	}
	// The caller holds the configuration lock and has validated the old store.
	_, err = os.Lstat(path + ".amnezia-receipts")
	exclusive := errors.Is(err, os.ErrNotExist)
	if err != nil && !exclusive {
		return err
	}
	return writeConfigAtomic(path+".amnezia-receipts", raw, 0600, os.Geteuid(), os.Getegid(), exclusive)
}
func (transaction *configTransaction) completeReceipts(rollback bool) error {
	if len(transaction.journal.NativeOriginal) == 0 {
		return nil
	}
	receipts, err := readConfigReceipts(transaction.path)
	if err != nil {
		return err
	}
	changed := false
	for id, record := range receipts.Records {
		if record.OriginalHash != transaction.journal.OriginalHash || record.CandidateHash != transaction.journal.CandidateHash {
			continue
		}
		if rollback {
			// A discarded pre-native stage must retain its intent for the bounded
			// restart. A persisted rollback direction invalidates a terminal commit.
			if transaction.journal.NativeRollbackHash == "" {
				continue
			}
			if record.State != "pending" && record.NativeOperation != transaction.journal.Operation {
				continue
			}
			record.State = "rolled-back"
		} else {
			if !transaction.journal.NativeApplied || transaction.journal.NativeRollbackHash != "" {
				return errors.New("native receipt lacks verified application")
			}
			if record.State != "pending" {
				continue
			}
			record.State = "committed"
		}
		record.NativeOperation = transaction.journal.Operation
		receipts.Records[id] = record
		changed = true
	}
	if changed {
		return writeConfigReceipts(transaction.path, receipts)
	}
	return nil
}
func configReceiptCommand(path string, request configTransactionRequest, output io.Writer) error {
	if !configOperationOK(request.Operation) || request.ServerIPv6 != "" || len(request.Expected) == 0 || len(request.Expected) > 4<<20 || len(request.Candidate) == 0 || len(request.Candidate) > 4<<20 {
		return errors.New("invalid receipt request")
	}
	lock, err := lockConfig(path)
	if err != nil {
		return err
	}
	defer lock.Close()
	receipts, err := readConfigReceipts(path)
	if err != nil {
		return err
	}
	record, exists := receipts.Records[request.Operation]
	originalHash, candidateHash := configHash(request.Expected), configHash(request.Candidate)
	if exists && (record.OriginalHash != originalHash || record.CandidateHash != candidateHash) {
		return errConfigConflict
	}
	if request.Action == "ack-receipt" {
		if exists {
			if record.State == "pending" {
				return errors.New("cannot acknowledge pending receipt")
			}
			if _, err := os.Lstat(path + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
				return errors.New("configuration transaction is pending")
			}
			delete(receipts.Records, request.Operation)
			if err := writeConfigReceipts(path, receipts); err != nil {
				return err
			}
		}
		return json.NewEncoder(output).Encode(map[string]any{"version": 1, "acknowledged": true, "operation": request.Operation})
	}
	if !exists {
		if request.Action != "prepare-receipt" {
			return errors.New("unknown configuration receipt")
		}
		if len(receipts.Records) >= maxConfigReceipts {
			return errors.New("configuration receipt capacity exhausted")
		}
		if _, err := os.Lstat(path + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("configuration transaction is pending")
		}
		current, info, err := readConfigFile(path, 4<<20)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 || !bytes.Equal(current, request.Expected) || !sameQuickSettings(request.Expected, request.Candidate) {
			return errConfigConflict
		}
		native, err := captureNativeProtocol(request.Container)
		if err != nil {
			return err
		}
		if err := verifyNativeConfigBaseline(request.Container, path, native); err != nil {
			return err
		}
		record = configReceipt{OriginalHash: originalHash, CandidateHash: candidateHash, State: "pending"}
		receipts.Records[request.Operation] = record
		if err := writeConfigReceipts(path, receipts); err != nil {
			return err
		}
	}
	if request.Action == "check-revoked-peer" {
		if record.State != "committed" {
			return errors.New("receipt is not committed")
		}
		if _, err := os.Lstat(path + ".amnezia-journal"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("configuration transaction is pending")
		}
		key, err := receiptRemovedPeer(request.Expected, request.Candidate)
		if err != nil {
			return err
		}
		_, info, err := readConfigFile(path, 4<<20)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 {
			return errConfigConflict
		}
		native, err := captureNativeProtocol(request.Container)
		if err != nil {
			return err
		}
		if err := verifyNativeConfigBaseline(request.Container, path, native); err != nil {
			return err
		}
		_, peers, err := iniInterface(native)
		if err != nil {
			return err
		}
		for _, peer := range peers {
			if peer == key {
				return errors.New("revoked peer is present again")
			}
		}
		return json.NewEncoder(output).Encode(map[string]any{"version": 1, "operation": request.Operation, "committed": true, "revoked": true, "clientPublicKey": key, "originalHash": originalHash, "candidateHash": candidateHash})
	}
	return json.NewEncoder(output).Encode(map[string]any{"version": 1, "operation": request.Operation, "state": record.State, "nativeOperation": record.NativeOperation, "originalHash": originalHash, "candidateHash": candidateHash})
}
func receiptRemovedPeer(original, candidate []byte) (string, error) {
	keys := func(raw []byte) (map[string]bool, error) {
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			lines[i] = strings.SplitN(line, "#", 2)[0]
		}
		_, peers, err := iniInterface([]byte(strings.Join(lines, "\n")))
		if err != nil {
			return nil, err
		}
		result := map[string]bool{}
		for _, key := range peers {
			if result[key] {
				return nil, errors.New("duplicate receipt peer")
			}
			result[key] = true
		}
		return result, nil
	}
	before, err := keys(original)
	if err != nil {
		return "", err
	}
	after, err := keys(candidate)
	if err != nil {
		return "", err
	}
	removed := ""
	for key := range before {
		if !after[key] {
			if removed != "" {
				return "", errors.New("ambiguous revoked peer")
			}
			removed = key
		}
	}
	for key := range after {
		if !before[key] {
			return "", errors.New("receipt adds another peer")
		}
	}
	if removed == "" {
		return "", errors.New("receipt does not revoke a peer")
	}
	return removed, nil
}

func validLegacyClientTable(raw []byte) bool {
	if len(raw) > 4<<20 || !utf8.Valid(raw) {
		return false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return true
	}
	var entries map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || entries == nil {
		return false
	}
	for key, value := range entries {
		var object map[string]json.RawMessage
		if key == "" || json.Unmarshal(value, &object) != nil || object == nil {
			return false
		}
	}
	return true
}
func clientTableMigrationPreserves(original, candidate []byte) bool {
	if validClientTable(original) || len(bytes.TrimSpace(original)) == 0 {
		return true
	}
	var old map[string]any
	var next []map[string]any
	decode := func(raw []byte, target any) bool {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		return decoder.Decode(target) == nil
	}
	if !decode(original, &old) || !decode(candidate, &next) {
		return false
	}
	for key, userData := range old {
		matches := 0
		for _, entry := range next {
			if entry["clientId"] == key {
				matches++
				if !equalMetadataJSON(entry["userData"], userData) {
					return false
				}
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

// Compare JSON numbers exactly without expanding exponents or rounding through
// float64. Serializer changes such as 1e3 -> 1000 must not block migration,
// whereas loss of a low bit in a large integer must be rejected.
func metadataNumber(raw string) (string, bool) {
	negative := strings.HasPrefix(raw, "-")
	if negative {
		raw = raw[1:]
	}
	parts := strings.SplitN(strings.ToLower(raw), "e", 2)
	mantissa := strings.SplitN(parts[0], ".", 2)
	fraction := 0
	digits := mantissa[0]
	if len(mantissa) == 2 {
		fraction = len(mantissa[1])
		digits += mantissa[1]
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0", true
	}
	trimmed := strings.TrimRight(digits, "0")
	trailing := len(digits) - len(trimmed)
	digits = trimmed
	exponent := int64(0)
	if len(parts) == 2 {
		var err error
		exponent, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return "", false
		}
	}
	power := big.NewInt(exponent)
	power.Add(power, big.NewInt(int64(trailing-fraction)))
	sign := ""
	if negative {
		sign = "-"
	}
	return sign + digits + "e" + power.String(), true
}
func equalMetadataJSON(left, right any) bool {
	switch a := left.(type) {
	case map[string]any:
		b, ok := right.(map[string]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for key, value := range a {
			other, exists := b[key]
			if !exists || !equalMetadataJSON(value, other) {
				return false
			}
		}
		return true
	case []any:
		b, ok := right.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for i, value := range a {
			if !equalMetadataJSON(value, b[i]) {
				return false
			}
		}
		return true
	case json.Number:
		b, ok := right.(json.Number)
		if !ok {
			return false
		}
		if a == b {
			return true
		}
		x, ok := metadataNumber(string(a))
		if !ok {
			return false
		}
		y, ok := metadataNumber(string(b))
		return ok && x == y
	case string:
		b, ok := right.(string)
		return ok && a == b
	case bool:
		b, ok := right.(bool)
		return ok && a == b
	case nil:
		return right == nil
	default:
		return false
	}
}
