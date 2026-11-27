package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestIPv6OnlyPublicationPreservesDeviceStateAndRetries(t *testing.T) {
	for _, container := range []string{"amnezia-wireguard", "amnezia-awg2"} {
		t.Run(container, func(t *testing.T) {
			dir := t.TempDir()
			info := mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
			a := mustAdmin(t, dir, "issue", request{Container: container, ClientPublicKey: testKey('A'), Settings: testSettings("vpn-a.example.test"), PathMTUProbe: "10.8.0.1"})
			b := mustAdmin(t, dir, "issue", request{Container: container, ClientPublicKey: testKey('B'), Settings: testSettings("vpn-b.example.test")})
			before, err := readState(dir)
			if err != nil {
				t.Fatal(err)
			}
			req := request{Container: container, Operation: strings.Repeat("1", 64), ExpectedState: stateTag(before), ClientIPv6: map[string]string{testKey('A'): "fd77::a", testKey('B'): "fd77::b"}}
			published := mustAdmin(t, dir, "publish-ipv6-if", req)
			if published["ok"] != true {
				t.Fatal("publication not confirmed")
			}
			after, err := readState(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before.SigningKey, after.SigningKey) || !bytes.Equal(before.Certificate, after.Certificate) || !bytes.Equal(before.TLSKey, after.TLSKey) {
				t.Fatal("delivery identity changed")
			}
			for _, issued := range []map[string]any{a, b} {
				id := issued["id"].(string)
				expected := before.Records[id]
				expected.Revision++
				address := req.ClientIPv6[expected.ClientPublicKey]
				expected.ClientIPv6 = &address
				if !reflect.DeepEqual(expected, after.Records[id]) {
					t.Fatal("unrelated device state changed")
				}
				got, present := signedClientIPv6(t, dir, id, issued["token"].(string), info["publicKey"].([]byte))
				if !present || got != address {
					t.Fatal("wrong signed client assignment")
				}
			}
			raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
			replay := mustAdmin(t, dir, "publish-ipv6-if", req)
			if replay["replayed"] != true {
				t.Fatal("retry not recognized")
			}
			current, _ := os.ReadFile(filepath.Join(dir, "state.json"))
			if !bytes.Equal(raw, current) {
				t.Fatal("retry changed state/revisions")
			}
			status := mustAdmin(t, dir, "ipv6-publication-status", request{Container: container, Operation: req.Operation})
			if status["known"] != true || status["current"] != true {
				t.Fatal("lost publication result cannot be recovered")
			}
			mutations := []request{req, req, req, req, req}
			mutations[0].Operation = strings.Repeat("2", 64)                     // stale state tag
			mutations[1].ClientIPv6 = map[string]string{testKey('A'): "fd77::c"} // reused operation
			mutations[2].Settings = testSettings("injected.example.test")
			mutations[3].ClientIPv6 = nil
			mutations[4].Operation = "invalid"
			for _, bad := range mutations {
				if _, err := admin(dir, "publish-ipv6-if", bad); err == nil {
					t.Fatal("invalid publication accepted")
				}
				current, _ = os.ReadFile(filepath.Join(dir, "state.json"))
				if !bytes.Equal(raw, current) {
					t.Fatal("rejected publication wrote state")
				}
			}
		})
	}
}
func TestIPv6PublicationDoesNotOverwriteConcurrentAdminChanges(t *testing.T) {
	dir := t.TempDir()
	info := mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	issued := mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: testKey('A'), Settings: testSettings("vpn.example.test")})
	before, _ := readState(dir)
	req := request{Container: "amnezia-wireguard", Operation: strings.Repeat("1", 64), ExpectedState: stateTag(before), ClientIPv6: map[string]string{testKey('A'): "fd77::a"}}
	mustAdmin(t, dir, "publish-ipv6-if", req)
	mustAdmin(t, dir, "issue", request{Container: "amnezia-awg2", ClientPublicKey: testKey('C'), Settings: testSettings("other.example.test")})
	// An unrelated container edit does not invalidate an already applied result.
	if mustAdmin(t, dir, "publish-ipv6-if", req)["replayed"] != true {
		t.Fatal("unrelated change hid completed operation")
	}
	changed := testSettings("new-endpoint.example.test")
	mustAdmin(t, dir, "publish", request{Container: req.Container, Settings: changed})
	status := mustAdmin(t, dir, "ipv6-publication-status", request{Container: req.Container, Operation: req.Operation})
	if status["known"] != true || status["current"] != false {
		t.Fatal("superseded operation reported current")
	}
	if _, err := admin(dir, "publish-ipv6-if", req); err == nil {
		t.Fatal("superseded operation replay accepted")
	}
	current, _ := readState(dir)
	withdraw := request{Container: req.Container, Operation: strings.Repeat("2", 64), ExpectedState: stateTag(current), ClientIPv6: map[string]string{testKey('A'): ""}}
	mustAdmin(t, dir, "publish-ipv6-if", withdraw)
	got, present := signedClientIPv6(t, dir, issued["id"].(string), issued["token"].(string), info["publicKey"].([]byte))
	if !present || got != "" {
		t.Fatal("withdrawal not signed")
	}
	after, _ := readState(dir)
	if !bytes.Equal(after.Records[issued["id"].(string)].Settings, changed) {
		t.Fatal("withdrawal reverted independent endpoint update")
	}
}
func TestIPv6PublicationReceiptCorruptionRejected(t *testing.T) {
	dir := t.TempDir()
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: testKey('A'), Settings: testSettings("vpn.example.test")})
	initial, _ := readState(dir)
	mustAdmin(t, dir, "publish-ipv6-if", request{Container: "amnezia-wireguard", Operation: strings.Repeat("1", 64), ExpectedState: stateTag(initial), ClientIPv6: map[string]string{testKey('A'): "fd77::a"}})
	valid, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	corrupt, _ := readState(dir)
	receipt := corrupt.IPv6Publications["amnezia-wireguard"]
	receipt.RequestHash = strings.Repeat("0", 64)
	corrupt.IPv6Publications["amnezia-wireguard"] = receipt
	if err := writeState(dir, corrupt); err == nil {
		t.Fatal("corrupt receipt saved")
	}
	unchanged, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if !bytes.Equal(valid, unchanged) {
		t.Fatal("rejection modified original state")
	}
	raw, _ := json.Marshal(corrupt)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(dir); err == nil {
		t.Fatal("corrupt receipt loaded")
	}
}

func TestIPv6PublicationAcceptsActualAdminWireEncoding(t *testing.T) {
	dir := t.TempDir()
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: testKey('A'), Settings: testSettings("vpn.example.test")})
	before, _ := readState(dir)
	original := request{Container: "amnezia-wireguard", Operation: strings.Repeat("1", 64), ExpectedState: stateTag(before), ClientIPv6: map[string]string{testKey('A'): "fd77::a"}}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var wire request
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	// Existing Go admin RPC encodes omitted RawMessage settings as JSON null.
	if string(wire.Settings) != "null" {
		t.Fatal("test does not exercise existing wire encoding")
	}
	mustAdmin(t, dir, "publish-ipv6-if", wire)
	raw, _ = json.Marshal(request{Container: wire.Container, Operation: wire.Operation})
	// Each RPC decodes into a fresh object.
	var status request
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	if mustAdmin(t, dir, "ipv6-publication-status", status)["current"] != true {
		t.Fatal("wire status query failed")
	}
}

func TestIPv6PublicationRetryDetectsNewAlias(t *testing.T) {
	dir := t.TempDir()
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: testKey('A'), Settings: testSettings("vpn.example.test")})
	before, _ := readState(dir)
	req := request{Container: "amnezia-wireguard", Operation: strings.Repeat("1", 64), ExpectedState: stateTag(before), ClientIPv6: map[string]string{testKey('A'): "fd77::a"}}
	mustAdmin(t, dir, "publish-ipv6-if", req)
	mustAdmin(t, dir, "issue", request{Container: req.Container, ClientPublicKey: testKey('A'), Settings: testSettings("alias.example.test")})
	if _, err := admin(dir, "publish-ipv6-if", req); err == nil {
		t.Fatal("new alias absent from original publication was ignored")
	}
	status := mustAdmin(t, dir, "ipv6-publication-status", request{Container: req.Container, Operation: req.Operation})
	if status["known"] != true || status["current"] != false {
		t.Fatal("new alias not reflected in publication status")
	}
}
