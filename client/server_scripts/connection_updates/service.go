// Connection updates deliberately cannot access the Docker socket or VPN keys.
// Administrative commands are available only through SSH + docker exec stdin.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxState = 4 << 20
const maxSettings = 32 << 10
const maxAdminRequest = maxState + maxSettings
const payloadType = "amnezia-connection-update"

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var awgKeys = strings.Fields("Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies")

type record struct {
	ClientIPv6      *string         `json:"clientIpv6,omitempty"`
	PathMTUProbe    string          `json:"pathMtuProbe,omitempty"`
	ID              string          `json:"id"`
	TokenHash       string          `json:"tokenHash"`
	ClientPublicKey string          `json:"clientPublicKey"`
	Container       string          `json:"container"`
	Revision        uint64          `json:"revision"`
	Revoked         bool            `json:"revoked"`
	Settings        json.RawMessage `json:"settings"`
}
type state struct {
	Host        string            `json:"host"`
	SigningKey  []byte            `json:"signingKey"`
	Certificate []byte            `json:"certificate"`
	TLSKey      []byte            `json:"tlsKey"`
	Records     map[string]record `json:"records"`
}
type request struct {
	ClientIPv6       map[string]string `json:"clientIpv6,omitempty"`
	PathMTUProbe     string            `json:"pathMtuProbe,omitempty"`
	ClientPublicKeys []string          `json:"clientPublicKeys"`
	ExpectedState    string            `json:"expectedState"`
	Host             string            `json:"host"`
	ClientPublicKey  string            `json:"clientPublicKey"`
	Container        string            `json:"container"`
	Settings         json.RawMessage   `json:"settings"`
}
type payload struct {
	Type            string          `json:"type"`
	Version         int             `json:"version"`
	ID              string          `json:"id"`
	ClientPublicKey string          `json:"clientPublicKey"`
	Container       string          `json:"container"`
	Revision        string          `json:"revision"`
	IssuedAt        int64           `json:"issuedAt"`
	ExpiresAt       int64           `json:"expiresAt"`
	Settings        json.RawMessage `json:"settings"`
}
type envelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func hostOK(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 || host != strings.ToLower(host) {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	numeric := true
	for _, part := range labels {
		if !hostLabel.MatchString(part) {
			return false
		}
		for _, value := range part {
			if value < '0' || value > '9' {
				numeric = false
			}
		}
	}
	return !numeric
}
func keyOK(s string) bool {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == s
}
func containerOK(c string) bool {
	return c == "amnezia-wireguard" || c == "amnezia-awg2"
}
func settingsOK(raw json.RawMessage, container string) error {
	if !containerOK(container) || len(raw) > maxSettings {
		return errors.New("unsupported container or oversized settings")
	}
	var s map[string]json.RawMessage
	if json.Unmarshal(raw, &s) != nil || s == nil {
		return errors.New("invalid settings")
	}
	allowed := map[string]bool{"hostName": true, "port": true, "server_pub_key": true}
	if container != "amnezia-wireguard" {
		for _, k := range awgKeys {
			allowed[k] = true
		}
	}
	for k, v := range s {
		if !allowed[k] {
			return errors.New("unexpected setting")
		}
		if k != "port" {
			var value string
			if json.Unmarshal(v, &value) != nil || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
				return errors.New("invalid setting value")
			}
		}
	}
	var host, key string
	var port int
	if json.Unmarshal(s["hostName"], &host) != nil || !hostOK(host) || json.Unmarshal(s["server_pub_key"], &key) != nil || !keyOK(key) || json.Unmarshal(s["port"], &port) != nil || port < 1 || port > 65535 {
		return errors.New("invalid endpoint or server key")
	}
	return nil
}
func pathMTUProbeOK(value string) bool {
	if value == "" {
		return true
	}
	ip := net.ParseIP(value)
	return len(value) <= 64 && ip != nil && ip.String() == value && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// This is per-device metadata, never a container-wide public setting. An
// explicit empty value withdraws a managed address; omission preserves it.
func clientIPv6OK(value string) bool {
	if value == "" {
		return true
	}
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Is6() && !ip.Is4In6() && ip.Zone() == "" && ip.String() == value &&
		ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() && !netip.MustParsePrefix("::/96").Contains(ip)
}
func clientIPv6AssignmentsOK(assignments map[string]string) error {
	seen := map[string]string{}
	for key, address := range assignments {
		if !keyOK(key) || !clientIPv6OK(address) {
			return errors.New("invalid client IPv6 assignment")
		}
		if address == "" {
			continue
		}
		if previous, exists := seen[address]; exists && previous != key {
			return errors.New("duplicate client IPv6 assignment")
		}
		seen[address] = key
	}
	return nil
}
func clientIPv6StateOK(s *state) error {
	seen := map[string]string{}
	for _, rec := range s.Records {
		if rec.ClientIPv6 == nil {
			continue
		}
		if !clientIPv6OK(*rec.ClientIPv6) {
			return errors.New("invalid saved client IPv6 assignment")
		}
		if rec.Revoked || *rec.ClientIPv6 == "" {
			continue
		}
		address := rec.Container + "|" + *rec.ClientIPv6
		if previous, exists := seen[address]; exists && previous != rec.ClientPublicKey {
			return errors.New("duplicate saved client IPv6 assignment")
		}
		seen[address] = rec.ClientPublicKey
	}
	return nil
}

func readState(dir string) (*state, error) {
	f, e := os.Open(filepath.Join(dir, "state.json"))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxState+1))
	if e != nil || len(b) > maxState {
		return nil, errors.New("cannot read state")
	}
	var s state
	if json.Unmarshal(b, &s) != nil || len(s.SigningKey) != ed25519.PrivateKeySize || s.Records == nil {
		return nil, errors.New("invalid state")
	}
	for _, rec := range s.Records {
		if !pathMTUProbeOK(rec.PathMTUProbe) {
			return nil, errors.New("invalid path probe address")
		}
	}
	if err := clientIPv6StateOK(&s); err != nil {
		return nil, err
	}
	return &s, nil
}
func writeState(dir string, s *state) error {
	if err := clientIPv6StateOK(s); err != nil {
		return err
	}
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if len(b) > maxState {
		return errors.New("state capacity reached")
	}
	f, e := os.CreateTemp(dir, ".state-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, filepath.Join(dir, "state.json")); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func newState(host string) (*state, error) {
	if !hostOK(host) {
		return nil, errors.New("invalid host")
	}
	_, sign, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	cert, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return &state{Host: host, SigningKey: sign, Certificate: cert, TLSKey: der, Records: map[string]record{}}, nil
}
func stateTag(s *state) string {
	raw, _ := json.Marshal(s)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
func info(s *state) map[string]any {
	return map[string]any{"version": 1, "stateTag": stateTag(s), "features": []string{"coverage-v1", "conditional-publication-v1", "awg3-header-protection-v1", "rollout-readiness-v1", "live-publication-v1", "path-mtu-probe-v1"}, "host": s.Host, "publicKey": []byte(ed25519.PrivateKey(s.SigningKey).Public().(ed25519.PublicKey)), "certificate": s.Certificate}
}
func probe(s *state) error {
	certificate, e := x509.ParseCertificate(s.Certificate)
	if e != nil {
		return e
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	dialer := tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: s.Host, MinVersion: tls.VersionTLS12}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, e := dialer.DialContext(ctx, "tcp", "127.0.0.1:8443")
	if e != nil {
		return e
	}
	return connection.Close()
}
func admin(dir, command string, req request) (map[string]any, error) {
	if command == "readiness" {
		return queryReadiness(req)
	}
	if command == "info" || command == "probe" {
		s, e := readState(dir)
		if e != nil {
			return nil, e
		}
		if command == "probe" {
			if e = probe(s); e != nil {
				return nil, e
			}
		}
		return info(s), nil
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if e := os.Chmod(dir, 0700); e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); e != nil {
		return nil, e
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	s, e := readState(dir)
	if command == "init" && errors.Is(e, os.ErrNotExist) {
		s, e = newState(req.Host)
		if e == nil {
			e = writeState(dir, s)
		}
	}
	if e != nil {
		return nil, e
	}
	if command == "init" && req.Host != s.Host {
		return nil, errors.New("existing certificate is for a different host")
	}
	out := info(s)
	switch command {
	case "init", "info":
		return out, nil
	case "issue":
		if err := clientIPv6AssignmentsOK(req.ClientIPv6); err != nil {
			return nil, err
		}
		if !pathMTUProbeOK(req.PathMTUProbe) {
			return nil, errors.New("invalid path probe address")
		}
		if !keyOK(req.ClientPublicKey) {
			return nil, errors.New("invalid client key")
		}
		if e = settingsOK(req.Settings, req.Container); e != nil {
			return nil, e
		}
		id, e := randomHex(16)
		if e != nil {
			return nil, e
		}
		tokenBytes := make([]byte, 32)
		if _, e = rand.Read(tokenBytes); e != nil {
			return nil, e
		}
		token := base64.RawURLEncoding.EncodeToString(tokenBytes)
		hash := sha256.Sum256([]byte(token))
		s.Records[id] = record{ID: id, TokenHash: hex.EncodeToString(hash[:]), ClientPublicKey: req.ClientPublicKey, Container: req.Container, Revision: 1, Settings: req.Settings, PathMTUProbe: req.PathMTUProbe}
		if address, exists := req.ClientIPv6[req.ClientPublicKey]; exists {
			rec := s.Records[id]
			rec.ClientIPv6 = &address
			s.Records[id] = rec
		}
		out["id"] = id
		out["token"] = token
	case "coverage":
		if !containerOK(req.Container) {
			return nil, errors.New("invalid container")
		}
		covered := map[string]bool{}
		for _, r := range s.Records {
			if r.Container == req.Container && !r.Revoked {
				covered[r.ClientPublicKey] = true
			}
		}
		seen := map[string]bool{}
		missing := 0
		for _, key := range req.ClientPublicKeys {
			if !keyOK(key) {
				return nil, errors.New("invalid client key")
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			if !covered[key] {
				missing++
			}
		}
		out["total"] = len(seen)
		out["missing"] = missing
		out["covered"] = len(seen) - missing
		return out, nil
	case "publish", "publish-if", "publish-live", "publish-if-live":
		if err := clientIPv6AssignmentsOK(req.ClientIPv6); err != nil {
			return nil, err
		}
		if !pathMTUProbeOK(req.PathMTUProbe) {
			return nil, errors.New("invalid path probe address")
		}
		if strings.HasPrefix(command, "publish-if") && (req.ExpectedState == "" || req.ExpectedState != stateTag(s)) {
			return nil, errors.New("subscription state changed")
		}
		if e = settingsOK(req.Settings, req.Container); e != nil {
			return nil, e
		}
		liveOnly := strings.HasSuffix(command, "-live")
		peers := map[string]bool{}
		if liveOnly {
			if req.ClientPublicKeys == nil {
				return nil, errors.New("live peer list required")
			}
			for _, key := range req.ClientPublicKeys {
				if !keyOK(key) {
					return nil, errors.New("invalid live peer key")
				}
				peers[key] = true
			}
		}
		for id, r := range s.Records {
			if r.Container == req.Container && !r.Revoked {
				if liveOnly && !peers[r.ClientPublicKey] {
					r.Revoked = true
					s.Records[id] = r
					continue
				}
				if r.Revision == ^uint64(0) {
					return nil, errors.New("revision exhausted")
				}
				r.Revision++
				r.Settings = req.Settings
				if req.PathMTUProbe != "" {
					r.PathMTUProbe = req.PathMTUProbe
				}
				if address, exists := req.ClientIPv6[r.ClientPublicKey]; exists {
					r.ClientIPv6 = &address
				}
				s.Records[id] = r
			}
		}
	case "revoke":
		if !keyOK(req.ClientPublicKey) || !containerOK(req.Container) {
			return nil, errors.New("invalid client")
		}
		for id, r := range s.Records {
			if r.ClientPublicKey == req.ClientPublicKey && r.Container == req.Container {
				r.Revoked = true
				s.Records[id] = r
			}
		}
	default:
		return nil, errors.New("unknown command")
	}
	if e = writeState(dir, s); e != nil {
		return nil, e
	}
	out["ok"] = true
	out["stateTag"] = stateTag(s)
	return out, nil
}
func handler(dir string, books ...*readinessBook) http.Handler {
	book := newReadinessBook()
	if len(books) > 0 {
		book = books[0]
	}
	slots := make(chan struct{}, 4)
	var rateMu sync.Mutex
	allowance := 40.0
	checked := time.Now()
	allow := func() bool {
		rateMu.Lock()
		defer rateMu.Unlock()
		now := time.Now()
		allowance += now.Sub(checked).Seconds() * 20
		checked = now
		if allowance > 40 {
			allowance = 40
		}
		if allowance < 1 {
			return false
		}
		allowance--
		return true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !allow() {
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", 503)
			return
		}
		ackRequest := r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/ack")
		if (r.Method != "GET" && !ackRequest) || r.URL.RawQuery != "" || !strings.HasPrefix(r.URL.Path, "/v1/connections/") {
			http.NotFound(w, r)
			return
		}
		path := r.URL.Path
		if ackRequest {
			path = strings.TrimSuffix(path, "/ack")
		}
		id := strings.TrimPrefix(path, "/v1/connections/")
		if !idPattern.MatchString(id) {
			http.NotFound(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || len(auth) != 50 {
			http.Error(w, "unauthorized", 401)
			return
		}
		s, e := readState(dir)
		if e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		rec, ok := s.Records[id]
		hash := sha256.Sum256([]byte(strings.TrimPrefix(auth, "Bearer ")))
		expected, e := hex.DecodeString(rec.TokenHash)
		if !ok || rec.Revoked || e != nil || subtle.ConstantTimeCompare(expected, hash[:]) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if ackRequest {
			var ack acknowledgement
			raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
			if e != nil || json.Unmarshal(raw, &ack) != nil || book.acknowledge(s, rec, ack, time.Now()) != nil {
				http.Error(w, "invalid acknowledgement", 400)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if book.challenge != nil {
			w.Header().Set("X-Amnezia-Update-Features", "ack-v1")
		}
		now := time.Now().Unix()
		p := payload{payloadType, 1, rec.ID, rec.ClientPublicKey, rec.Container, strconv.FormatUint(rec.Revision, 10), now, now + 600, rec.Settings}
		b, e := json.Marshal(p)
		if e == nil && (book.challenge != nil || rec.PathMTUProbe != "" || rec.ClientIPv6 != nil) {
			var signed map[string]json.RawMessage
			e = json.Unmarshal(b, &signed)
			if e == nil {
				if book.challenge != nil {
					signed["ackChallenge"], e = json.Marshal(book.publicChallenge())
				}
				if e == nil && rec.PathMTUProbe != "" {
					signed["pathMtuProbe"], e = json.Marshal(rec.PathMTUProbe)
				}
				if e == nil && rec.ClientIPv6 != nil {
					signed["clientIpv6"], e = json.Marshal(*rec.ClientIPv6)
				}
			}
			if e == nil {
				b, e = json.Marshal(signed)
			}
		}
		if e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(envelope{b, ed25519.Sign(s.SigningKey, b)})
	})
}
func run() error {
	dir := os.Getenv("AMNEZIA_UPDATES_STATE")
	if dir == "" {
		dir = "/data"
	}
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if command == "activate-awg3" {
		b, e := io.ReadAll(io.LimitReader(os.Stdin, maxAdminRequest+1))
		if e != nil {
			return errors.New("invalid request")
		}
		req, e := decodeRolloutRequest(b)
		if e != nil {
			return e
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		result := runRollout(ctx, req)
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if command != "serve" {
		b, e := io.ReadAll(io.LimitReader(os.Stdin, maxAdminRequest+1))
		if e != nil || len(b) > maxAdminRequest {
			return errors.New("invalid request")
		}
		var req request
		if len(b) > 0 && json.Unmarshal(b, &req) != nil {
			return errors.New("invalid request")
		}
		result, e := admin(dir, command, req)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	s, e := readState(dir)
	if e != nil {
		return e
	}
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: s.TLSKey}))
	if e != nil {
		return e
	}
	book := newReadinessBook()
	readiness, e := serveReadiness(readinessSocket, dir, book)
	if e != nil {
		return e
	}
	defer readiness.Close()
	server := deliveryHTTPServer(dir, book, cert)
	return server.ListenAndServeTLS("", "")
}
func deliveryHTTPServer(dir string, book *readinessBook, certificate tls.Certificate) *http.Server {
	return &http.Server{Addr: ":8443", Handler: handler(dir, book),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
		ErrorLog:  log.New(io.Discard, "", 0)}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "connection updates: operation failed:", e)
		os.Exit(1)
	}
}
