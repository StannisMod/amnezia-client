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

func TestPathProbeMigrationPreservesLegacySettingsAndIdentity(t *testing.T) {
	for _, address := range []string{"10.77.0.9", "fd77::1"} {
		t.Run(address, func(t *testing.T) {
			dir := t.TempDir()
			info := mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
			settings := testSettings("vpn.example.test")
			issued := mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: testKey('C'), Settings: settings})
			id, token := issued["id"].(string), issued["token"].(string)
			before, _ := readState(dir)
			identity := before.Records[id]
			mustAdmin(t, dir, "publish", request{Container: "amnezia-wireguard", Settings: settings, PathMTUProbe: address})
			after, e := readState(dir)
			if e != nil {
				t.Fatal(e)
			}
			rec := after.Records[id]
			if rec.ID != identity.ID || rec.TokenHash != identity.TokenHash || rec.ClientPublicKey != identity.ClientPublicKey || rec.Revision != 2 || rec.PathMTUProbe != address {
				t.Fatal("migration changed identity or lost probe")
			}
			req := httptest.NewRequest(http.MethodGet, "/v1/connections/"+id, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler(dir).ServeHTTP(response, req)
			var env envelope
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &env) != nil || !ed25519.Verify(info["publicKey"].([]byte), env.Payload, env.Signature) {
				t.Fatal("invalid signed migration", response.Code)
			}
			var old payload
			if json.Unmarshal(env.Payload, &old) != nil || !bytes.Equal(canonicalSettings(old.Settings), canonicalSettings(settings)) || settingsOK(old.Settings, old.Container) != nil {
				t.Fatal("legacy settings became incompatible")
			}
			var fields map[string]json.RawMessage
			json.Unmarshal(env.Payload, &fields)
			var target string
			json.Unmarshal(fields["pathMtuProbe"], &target)
			if target != address {
				t.Fatal("probe not signed")
			}
			mustAdmin(t, dir, "publish", request{Container: "amnezia-wireguard", Settings: settings})
			kept, _ := readState(dir)
			if kept.Records[id].PathMTUProbe != address {
				t.Fatal("legacy publisher erased probe")
			}
		})
	}
}

func TestPathProbeRejectsInvalidAddressWithoutWritingState(t *testing.T) {
	dir := t.TempDir()
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	settings := testSettings("vpn.example.test")
	mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: testKey('C'), Settings: settings})
	original, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	for _, value := range []string{"vpn.example.test", "127.0.0.1", "0.0.0.0", "224.0.0.1", "::", "::1", "fe80::1", "fd77::1%wlan0", "::ffff:10.77.0.1", "10.77.0.1\n"} {
		if _, err := admin(dir, "publish", request{Container: "amnezia-wireguard", Settings: settings, PathMTUProbe: value}); err == nil {
			t.Fatal("invalid target accepted", value)
		}
		current, _ := os.ReadFile(filepath.Join(dir, "state.json"))
		if !bytes.Equal(current, original) {
			t.Fatal("rejected migration wrote state", value)
		}
	}
}

func TestPathProbeWireFixture(t *testing.T) {
	original, err := os.ReadFile("../../tests/connection-updates/interop.json")
	if err != nil {
		t.Fatal(err)
	}
	var base struct {
		Envelope envelope `json:"envelope"`
	}
	if json.Unmarshal(original, &base) != nil {
		t.Fatal("invalid base fixture")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(base.Envelope.Payload, &fields) != nil {
		t.Fatal("invalid base payload")
	}
	fields["pathMtuProbe"], _ = json.Marshal("10.8.0.1")
	raw, _ := json.Marshal(fields)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'S'}, 32))
	fixture := map[string]any{"publicKey": []byte(key.Public().(ed25519.PublicKey)), "envelope": envelope{raw, ed25519.Sign(key, raw)}}
	expected, _ := json.MarshalIndent(fixture, "", "  ")
	expected = append(expected, '\n')
	path := "../../tests/connection-updates/path-probe-interop.json"
	if os.Getenv("UPDATE_FIXTURE") == "1" {
		if err := os.WriteFile(path, expected, 0644); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("Go/Qt path probe fixture changed", err)
	}
}
