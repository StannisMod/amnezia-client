package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func signedClientIPv6(t *testing.T, dir, id, token string, public []byte) (string, bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/connections/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler(dir).ServeHTTP(response, req)
	var env envelope
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &env) != nil || !ed25519.Verify(public, env.Payload, env.Signature) {
		t.Fatal("invalid signed client address response", response.Code)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(env.Payload, &fields) != nil {
		t.Fatal("invalid payload")
	}
	var address string
	raw, exists := fields["clientIpv6"]
	if exists && json.Unmarshal(raw, &address) != nil {
		t.Fatal("invalid address encoding")
	}
	var legacy payload
	if json.Unmarshal(env.Payload, &legacy) != nil || settingsOK(legacy.Settings, legacy.Container) != nil {
		t.Fatal("extension broke legacy settings")
	}
	return address, exists
}

func TestSignedClientIPv6PreservesKeysAndIsolatesDevices(t *testing.T) {
	for _, container := range []string{"amnezia-wireguard", "amnezia-awg2"} {
		t.Run(container, func(t *testing.T) {
			dir := t.TempDir()
			info := mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
			settings := testSettings("vpn.example.test")
			a := mustAdmin(t, dir, "issue", request{Container: container, ClientPublicKey: testKey('A'), Settings: settings})
			b := mustAdmin(t, dir, "issue", request{Container: container, ClientPublicKey: testKey('B'), Settings: settings})
			before, _ := readState(dir)
			for _, issued := range []map[string]any{a, b} {
				if _, present := signedClientIPv6(t, dir, issued["id"].(string), issued["token"].(string), info["publicKey"].([]byte)); present {
					t.Fatal("legacy record acquired an invented address")
				}
			}
			mustAdmin(t, dir, "publish", request{Container: container, Settings: settings, ClientIPv6: map[string]string{testKey('A'): "fd77::a", testKey('B'): "fd77::b"}})
			after, _ := readState(dir)
			for i, issued := range []map[string]any{a, b} {
				id := issued["id"].(string)
				old, current := before.Records[id], after.Records[id]
				if old.ID != current.ID || old.ClientPublicKey != current.ClientPublicKey || old.TokenHash != current.TokenHash || current.Revision != old.Revision+1 || !bytes.Equal(old.Settings, current.Settings) {
					t.Fatal("IPv6 publication changed client identity/settings")
				}
				expected := []string{"fd77::a", "fd77::b"}[i]
				got, present := signedClientIPv6(t, dir, id, issued["token"].(string), info["publicKey"].([]byte))
				if !present || got != expected {
					t.Fatal("address crossed client identity", got)
				}
			}
			// A publisher unaware of the extension must not erase an existing assignment.
			mustAdmin(t, dir, "publish", request{Container: container, Settings: settings})
			got, present := signedClientIPv6(t, dir, a["id"].(string), a["token"].(string), info["publicKey"].([]byte))
			if !present || got != "fd77::a" {
				t.Fatal("legacy publisher erased assignment")
			}
			// Withdrawal is explicit and signed, and does not affect another device.
			mustAdmin(t, dir, "publish", request{Container: container, Settings: settings, ClientIPv6: map[string]string{testKey('A'): ""}})
			got, present = signedClientIPv6(t, dir, a["id"].(string), a["token"].(string), info["publicKey"].([]byte))
			if !present || got != "" {
				t.Fatal("signed withdrawal missing")
			}
			got, present = signedClientIPv6(t, dir, b["id"].(string), b["token"].(string), info["publicKey"].([]byte))
			if !present || got != "fd77::b" {
				t.Fatal("withdrawal affected another device")
			}
		})
	}
}

func TestClientIPv6RejectsInvalidOrCollidingAssignmentsAtomically(t *testing.T) {
	dir := t.TempDir()
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	settings := testSettings("vpn.example.test")
	mustAdmin(t, dir, "issue", request{Container: "amnezia-awg2", ClientPublicKey: testKey('A'), Settings: settings, ClientIPv6: map[string]string{testKey('A'): "fd77::a"}})
	// Use a WG pair to test collision with a preserved assignment omitted by a partial publisher.
	mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: testKey('A'), Settings: settings, ClientIPv6: map[string]string{testKey('A'): "fd77::a"}})
	mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: testKey('B'), Settings: settings})
	original, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	bad := []string{"10.77.0.2", "::", "::1", "ff02::1", "fe80::1", "fd77::a%eth0", "::ffff:10.77.0.2", "::c000:201", "FD77::A", "fd77::a/128", "fd77::a\n", "vpn.example.test", "fd77::a"}
	for _, address := range bad {
		if _, err := admin(dir, "publish", request{Container: "amnezia-wireguard", Settings: settings, ClientIPv6: map[string]string{testKey('B'): address}}); err == nil {
			t.Fatal("invalid/colliding assignment accepted", address)
		}
		current, _ := os.ReadFile(filepath.Join(dir, "state.json"))
		if !bytes.Equal(original, current) {
			t.Fatal("rejected assignment changed persistent state")
		}
	}
	if _, err := admin(dir, "publish", request{Container: "amnezia-wireguard", Settings: settings, ClientIPv6: map[string]string{testKey('A'): "fd77::b", testKey('B'): "fd77::b"}}); err == nil {
		t.Fatal("duplicate request addresses accepted")
	}
	if _, err := admin(dir, "publish", request{Container: "amnezia-wireguard", Settings: settings, ClientIPv6: map[string]string{"invalid-key": "fd77::b"}}); err == nil {
		t.Fatal("invalid device identity accepted")
	}
	s, _ := readState(dir)
	for id, rec := range s.Records {
		if rec.Container == "amnezia-wireguard" && rec.ClientPublicKey == testKey('A') {
			invalid := "::1"
			rec.ClientIPv6 = &invalid
			s.Records[id] = rec
			break
		}
	}
	raw, _ := json.Marshal(s)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(dir); err == nil {
		t.Fatal("corrupt saved assignment accepted")
	}
}
