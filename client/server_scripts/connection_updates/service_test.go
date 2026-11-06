package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func testKey(c byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{c}, 32)) }
func testSettings(host string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"hostName": host, "port": 51821, "server_pub_key": testKey('P')})
	return b
}
func mustAdmin(t *testing.T, dir, cmd string, req request) map[string]any {
	t.Helper()
	out, e := admin(dir, cmd, req)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestLifecycle(t *testing.T) {
	dir := t.TempDir()
	init := mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	original, e := os.ReadFile(filepath.Join(dir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	unchanged, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if !bytes.Equal(original, unchanged) {
		t.Fatal("init rewrote identity")
	}
	if _, e = admin(dir, "init", request{Host: "other.example.test"}); e == nil {
		t.Fatal("changed TLS host accepted")
	}
	req := request{Container: "amnezia-wireguard", ClientPublicKey: testKey('C'), Settings: testSettings("vpn1.example.test")}
	issued := mustAdmin(t, dir, "issue", req)
	id := issued["id"].(string)
	token := issued["token"].(string)
	s, e := readState(dir)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if bytes.Contains(raw, []byte(token)) {
		t.Fatal("stored bearer token")
	}
	// Real TLS listener and certificate verification; no insecure TLS bypass.
	cert, e := tls.X509KeyPair(pemCertificate(s.Certificate), pemPrivateKey(s.TLSKey))
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(handler(dir))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	defer server.Close()
	pool := x509.NewCertPool()
	parsed, e := x509.ParseCertificate(s.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	pool.AddCert(parsed)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	fetch := func(tok, path string, status int) payload {
		t.Helper()
		r, _ := http.NewRequest("GET", server.URL+path, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		b, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		if response.StatusCode != status {
			t.Fatalf("status %d, want %d", response.StatusCode, status)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache enabled")
		}
		if status != 200 {
			return payload{}
		}
		var env envelope
		if json.Unmarshal(b, &env) != nil || !ed25519.Verify(init["publicKey"].([]byte), env.Payload, env.Signature) {
			t.Fatal("invalid signature")
		}
		var p payload
		if json.Unmarshal(env.Payload, &p) != nil {
			t.Fatal("invalid payload")
		}
		return p
	}
	path := "/v1/connections/" + id
	if p := fetch(token, path, 200); p.Revision != "1" || p.ClientPublicKey != req.ClientPublicKey || p.ExpiresAt-p.IssuedAt != 600 {
		t.Fatal("wrong identity/revision/validity")
	}
	fetch("bad", path, 401)
	fetch(token, path+"?token=leak", 404)
	fetch(token, "/v1/connections/../../state.json", 404)
	// Concurrent admin processes cannot lose revisions or silently resurrect tokens.
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := admin(dir, "publish", request{Container: req.Container, Settings: testSettings("vpn2.example.test")}); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if p := fetch(token, path, 200); p.Revision != "6" || !bytes.Contains(p.Settings, []byte("vpn2.example.test")) {
		t.Fatal("lost publication")
	}
	mustAdmin(t, dir, "revoke", req)
	fetch(token, path, 401)
	mustAdmin(t, dir, "publish", request{Container: req.Container, Settings: testSettings("vpn3.example.test")})
	fetch(token, path, 401)
	if mode, e := os.Stat(filepath.Join(dir, "state.json")); e != nil || mode.Mode().Perm() != 0600 {
		t.Fatal("state is not private")
	}
}
func TestRejectsPrivateAndUnsafeFields(t *testing.T) {
	for _, field := range []string{"client_priv_key", "config", "dns1", "allowed_ips", "PostUp", "token"} {
		var settings map[string]any
		json.Unmarshal(testSettings("vpn.example.test"), &settings)
		settings[field] = "private"
		raw, _ := json.Marshal(settings)
		if settingsOK(raw, "amnezia-wireguard") == nil {
			t.Fatalf("accepted %s", field)
		}
	}
	if settingsOK(testSettings("vpn.example.test"), "amnezia-openvpn") == nil {
		t.Fatal("unsupported protocol")
	}
	dir := t.TempDir()
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	if _, e := admin(dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: "bad", Settings: testSettings("vpn.example.test")}); e == nil {
		t.Fatal("invalid identity")
	}
	if _, e := readState(t.TempDir()); e == nil {
		t.Fatal("missing state read")
	}
}
func TestWireFixture(t *testing.T) {
	// Public synthetic test keys, deliberately deterministic across Go and OpenSSL.
	seed := bytes.Repeat([]byte{'S'}, 32)
	key := ed25519.NewKeyFromSeed(seed)
	device, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{'D'}, 32))
	if e != nil {
		t.Fatal(e)
	}
	p := payload{payloadType, 1, "0123456789abcdef0123456789abcdef", base64.StdEncoding.EncodeToString(device.PublicKey().Bytes()), "amnezia-wireguard", "1", 2000000000, 2000000600, testSettings("vpn2.example.test")}
	raw, _ := json.Marshal(p)
	fixture := map[string]any{"publicKey": []byte(key.Public().(ed25519.PublicKey)), "envelope": envelope{raw, ed25519.Sign(key, raw)}}
	expected, e := json.MarshalIndent(fixture, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	expected = append(expected, '\n')
	path := "../../tests/connection-updates/interop.json"
	if os.Getenv("UPDATE_FIXTURE") == "1" {
		if e = os.WriteFile(path, expected, 0644); e != nil {
			t.Fatal(e)
		}
	}
	actual, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("Go/Qt wire fixture changed")
	}
}

func pemCertificate(b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
}
func pemPrivateKey(b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}

func TestCapacityAndRateLimits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "volume")
	if e := os.Mkdir(dir, 0755); e != nil {
		t.Fatal(e)
	}
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	if st, e := os.Stat(dir); e != nil || st.Mode().Perm() != 0700 {
		t.Fatal("pre-existing volume directory is not private")
	}
	original, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	s, e := readState(dir)
	if e != nil {
		t.Fatal(e)
	}
	oversized := append([]byte(`{"value":"`), bytes.Repeat([]byte{'x'}, maxState)...)
	oversized = append(oversized, []byte(`"}`)...)
	s.Records["full"] = record{Settings: oversized}
	if writeState(dir, s) == nil {
		t.Fatal("oversized state committed")
	}
	current, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if !bytes.Equal(original, current) {
		t.Fatal("capacity failure changed committed state")
	}
	h := handler(dir)
	limited := false
	for i := 0; i < 100; i++ {
		out := httptest.NewRecorder()
		h.ServeHTTP(out, httptest.NewRequest("GET", "/invalid", nil))
		if out.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("unbounded request rate")
	}
}
