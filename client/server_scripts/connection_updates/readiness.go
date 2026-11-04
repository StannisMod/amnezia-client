package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const readinessSocket = "/run/amnezia-updates/readiness.sock"
const protectionFeature = "awg3-header-protection-v1"
const readinessDomain = "amnezia-awg3-ready-v1\x00"

type acknowledgement struct {
	envelope
	Features []string `json:"features"`
	Proof    []byte   `json:"proof"`
}
type readinessEntry struct {
	Revision     uint64
	TokenHash    string
	SettingsHash [32]byte
	Seen         time.Time
}
type readinessBook struct {
	mu        sync.Mutex
	entries   map[string]readinessEntry
	challenge *ecdh.PrivateKey
}

func newReadinessBook() *readinessBook {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return &readinessBook{entries: map[string]readinessEntry{}, challenge: key}
}
func (book *readinessBook) publicChallenge() []byte {
	if book.challenge == nil {
		return nil
	}
	return book.challenge.PublicKey().Bytes()
}
func readinessMAC(shared, payload []byte) []byte {
	mac := hmac.New(sha256.New, shared)
	mac.Write([]byte(readinessDomain))
	mac.Write(payload)
	return mac.Sum(nil)
}
func canonicalSettings(raw json.RawMessage) []byte {
	var values map[string]any
	if json.Unmarshal(raw, &values) != nil {
		return nil
	}
	result, _ := json.Marshal(values)
	return result
}
func (book *readinessBook) acknowledge(s *state, rec record, ack acknowledgement, now time.Time) error {
	feature := false
	for _, value := range ack.Features {
		if value == protectionFeature {
			feature = true
		}
	}
	if !feature || len(ack.Payload) > 65536 || len(ack.Signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PrivateKey(s.SigningKey).Public().(ed25519.PublicKey), ack.Payload, ack.Signature) {
		return errors.New("invalid acknowledgement")
	}
	var p struct {
		payload
		AckChallenge []byte `json:"ackChallenge"`
	}
	if json.Unmarshal(ack.Payload, &p) != nil || p.Type != payloadType || p.Version != 1 || p.ID != rec.ID || p.ClientPublicKey != rec.ClientPublicKey || p.Container != rec.Container || p.Revision != strconv.FormatUint(rec.Revision, 10) || p.ExpiresAt <= now.Unix() || p.IssuedAt > now.Unix()+300 || !bytes.Equal(canonicalSettings(p.Settings), canonicalSettings(rec.Settings)) {
		return errors.New("stale acknowledgement")
	}
	if book.challenge == nil || !bytes.Equal(p.AckChallenge, book.publicChallenge()) {
		return errors.New("wrong readiness epoch")
	}
	clientBytes, e := base64.StdEncoding.Strict().DecodeString(rec.ClientPublicKey)
	if e != nil {
		return errors.New("invalid client key")
	}
	clientKey, e := ecdh.X25519().NewPublicKey(clientBytes)
	if e != nil {
		return errors.New("invalid client key")
	}
	shared, e := book.challenge.ECDH(clientKey)
	if e != nil || !hmac.Equal(ack.Proof, readinessMAC(shared, ack.Payload)) {
		return errors.New("device key proof failed")
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	book.entries[rec.ID] = readinessEntry{Revision: rec.Revision, TokenHash: rec.TokenHash, SettingsHash: sha256.Sum256(canonicalSettings(rec.Settings)), Seen: now}
	return nil
}
func (book *readinessBook) report(s *state, req request, now time.Time) (map[string]any, error) {
	if !containerOK(req.Container) {
		return nil, errors.New("invalid container")
	}
	covered := map[string]bool{}
	ready := map[string]bool{}
	book.mu.Lock()
	defer book.mu.Unlock()
	for id, entry := range book.entries {
		rec, exists := s.Records[id]
		if !exists || rec.Revoked || entry.Seen.Before(now.Add(-24*time.Hour)) {
			delete(book.entries, id)
		}
	}
	for id, rec := range s.Records {
		if rec.Container != req.Container || rec.Revoked {
			continue
		}
		covered[rec.ClientPublicKey] = true
		entry, exists := book.entries[id]
		if exists && entry.SettingsHash == sha256.Sum256(canonicalSettings(rec.Settings)) && entry.TokenHash == rec.TokenHash {
			ready[rec.ClientPublicKey] = true
		}
	}
	total, missing, unready := 0, 0, 0
	seen := map[string]bool{}
	for _, key := range req.ClientPublicKeys {
		if !keyOK(key) {
			return nil, errors.New("invalid client key")
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		total++
		if !covered[key] {
			missing++
		}
		if !ready[key] {
			unready++
		}
	}
	result := info(s)
	result["total"] = total
	result["missing"] = missing
	result["notReady"] = unready
	return result, nil
}
func serveReadiness(path, dir string, book *readinessBook) (net.Listener, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	if old, e := os.Lstat(path); e == nil {
		if old.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("unexpected readiness path")
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	}
	listener, e := net.Listen("unix", path)
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		listener.Close()
		return nil, e
	}
	go func() {
		for {
			connection, e := listener.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var req request
				if json.NewDecoder(io.LimitReader(c, 65537)).Decode(&req) != nil {
					return
				}
				s, e := readState(dir)
				if e != nil {
					return
				}
				result, e := book.report(s, req, time.Now())
				if e != nil {
					return
				}
				_ = json.NewEncoder(c).Encode(result)
			}(connection)
		}
	}()
	return listener, nil
}
func queryReadiness(req request) (map[string]any, error) {
	connection, e := net.DialTimeout("unix", readinessSocket, 5*time.Second)
	if e != nil {
		return nil, e
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if e = json.NewEncoder(connection).Encode(req); e != nil {
		return nil, e
	}
	var result map[string]any
	if e = json.NewDecoder(io.LimitReader(connection, 65537)).Decode(&result); e != nil {
		return nil, e
	}
	return result, nil
}
