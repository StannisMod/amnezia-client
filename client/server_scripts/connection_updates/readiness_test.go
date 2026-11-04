package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func readinessFixture(t *testing.T) (*state, record, *ecdh.PrivateKey, *readinessBook, time.Time) {
	t.Helper()
	dir := t.TempDir()
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	device, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{'D'}, 32))
	if e != nil {
		t.Fatal(e)
	}
	mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: base64.StdEncoding.EncodeToString(device.PublicKey().Bytes()), Settings: testSettings("vpn2.example.test")})
	s, e := readState(dir)
	if e != nil {
		t.Fatal(e)
	}
	var rec record
	for _, r := range s.Records {
		rec = r
	}
	return s, rec, device, newReadinessBook(), time.Unix(2000000001, 0)
}
func makeReadinessAck(t *testing.T, s *state, rec record, device *ecdh.PrivateKey, book *readinessBook, now time.Time) acknowledgement {
	t.Helper()
	p := payload{payloadType, 1, rec.ID, rec.ClientPublicKey, rec.Container, "1", now.Unix(), now.Unix() + 600, rec.Settings}
	raw := mustJSON(p)
	var values map[string]json.RawMessage
	json.Unmarshal(raw, &values)
	values["ackChallenge"] = mustJSON(book.publicChallenge())
	raw = mustJSON(values)
	shared, e := device.ECDH(book.challenge.PublicKey())
	if e != nil {
		t.Fatal(e)
	}
	return acknowledgement{envelope: envelope{raw, ed25519.Sign(s.SigningKey, raw)}, Features: []string{protectionFeature}, Proof: readinessMAC(shared, raw)}
}
func TestReadinessRequiresOwnedDeviceAndCurrentParameters(t *testing.T) {
	s, rec, device, book, now := readinessFixture(t)
	req := request{Container: rec.Container, ClientPublicKeys: []string{rec.ClientPublicKey}}
	report, e := book.report(s, req, now)
	if e != nil || report["notReady"] != 1 {
		t.Fatal("issued token incorrectly proved readiness")
	}
	ack := makeReadinessAck(t, s, rec, device, book, now)
	missing := ack
	missing.Proof = nil
	if book.acknowledge(s, rec, missing, now) == nil {
		t.Fatal("bare token holder proved device ownership")
	}
	wrong := ack
	wrong.Proof = bytes.Repeat([]byte{'X'}, 32)
	if book.acknowledge(s, rec, wrong, now) == nil {
		t.Fatal("wrong device proof accepted")
	}
	if book.acknowledge(s, rec, ack, now) != nil {
		t.Fatal("valid acknowledgement rejected")
	}
	report, e = book.report(s, req, now)
	if e != nil || report["notReady"] != 0 {
		t.Fatal("valid device not ready")
	}
	if book.acknowledge(s, rec, ack, now.Add(601*time.Second)) == nil {
		t.Fatal("expired receipt accepted")
	}
	fresh := newReadinessBook()
	if fresh.acknowledge(s, rec, ack, now) == nil {
		t.Fatal("old server epoch accepted")
	}
	changed := rec
	changed.Revision++
	changed.Settings = testSettings("vpn3.example.test")
	s.Records[rec.ID] = changed
	report, _ = book.report(s, req, now)
	if report["notReady"] != 1 {
		t.Fatal("changed settings did not require confirmation")
	}
	changed.Revision++
	changed.Settings = rec.Settings
	s.Records[rec.ID] = changed
	report, _ = book.report(s, req, now)
	if report["notReady"] != 0 {
		t.Fatal("identical rollback settings lost proven readiness")
	}
	changed.Revoked = true
	s.Records[rec.ID] = changed
	report, _ = book.report(s, req, now)
	if report["notReady"] != 1 || report["missing"] != 1 {
		t.Fatal("revoked token stayed ready")
	}
}
func TestReadinessHttpAcknowledgement(t *testing.T) {
	dir := t.TempDir()
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	device, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{'D'}, 32))
	pub := base64.StdEncoding.EncodeToString(device.PublicKey().Bytes())
	issued := mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: pub, Settings: testSettings("vpn.example.test")})
	id, token := issued["id"].(string), issued["token"].(string)
	book := newReadinessBook()
	h := handler(dir, book)
	get := httptest.NewRequest("GET", "/v1/connections/"+id, nil)
	get.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, get)
	if response.Code != 200 || response.Header().Get("X-Amnezia-Update-Features") != "ack-v1" {
		t.Fatal("readiness capability missing")
	}
	var env envelope
	if json.Unmarshal(response.Body.Bytes(), &env) != nil {
		t.Fatal("invalid envelope")
	}
	var p struct {
		payload
		AckChallenge []byte `json:"ackChallenge"`
	}
	json.Unmarshal(env.Payload, &p)
	peer, e := ecdh.X25519().NewPublicKey(p.AckChallenge)
	if e != nil {
		t.Fatal(e)
	}
	shared, e := device.ECDH(peer)
	if e != nil {
		t.Fatal(e)
	}
	ack := acknowledgement{envelope: env, Features: []string{protectionFeature}, Proof: readinessMAC(shared, env.Payload)}
	post := httptest.NewRequest("POST", "/v1/connections/"+id+"/ack", bytes.NewReader(mustJSON(ack)))
	post.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, post)
	if response.Code != http.StatusNoContent {
		t.Fatal("receipt rejected")
	}
	s, _ := readState(dir)
	report, e := book.report(s, request{Container: "amnezia-wireguard", ClientPublicKeys: []string{pub}}, time.Now())
	if e != nil || report["notReady"] != 0 {
		t.Fatal("receipt not visible through readiness")
	}
}
func TestReadinessWireFixture(t *testing.T) {
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'S'}, 32))
	device, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{'D'}, 32))
	ephemeral, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{'R'}, 32))
	p := payload{payloadType, 1, "0123456789abcdef0123456789abcdef", base64.StdEncoding.EncodeToString(device.PublicKey().Bytes()), "amnezia-wireguard", "1", 2000000000, 2000000600, testSettings("vpn2.example.test")}
	raw := mustJSON(p)
	var values map[string]json.RawMessage
	json.Unmarshal(raw, &values)
	values["ackChallenge"] = mustJSON(ephemeral.PublicKey().Bytes())
	raw = mustJSON(values)
	shared, _ := device.ECDH(ephemeral.PublicKey())
	fixture := map[string]any{"envelope": envelope{raw, ed25519.Sign(signer, raw)}, "proof": readinessMAC(shared, raw)}
	expected, e := json.MarshalIndent(fixture, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	expected = append(expected, '\n')
	path := "../../tests/connection-updates/readiness-interop.json"
	if os.Getenv("UPDATE_FIXTURE") == "1" {
		if e = os.WriteFile(path, expected, 0644); e != nil {
			t.Fatal(e)
		}
	}
	actual, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(expected, actual) {
		t.Fatal("Go/OpenSSL readiness fixture changed")
	}
}
