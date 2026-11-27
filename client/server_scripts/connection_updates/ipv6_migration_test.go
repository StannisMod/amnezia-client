package main

import (
	"bytes"
	"strings"
	"testing"
)

func migrationConfig() string {
	return "# original configuration\n[Interface]\nPrivateKey = preserve-private-key\nAddress = 10.8.0.1/24 # local interface\nListenPort = 51820\nH1 = 12345\n\n[Peer]\nPublicKey = " + testKey('A') + "\nPresharedKey = preserve-psk-A\nAllowedIPs = 10.8.0.2/32 # first client\n\n[Peer]\nPublicKey = " + testKey('B') + "\nPresharedKey = preserve-psk-B\nAllowedIPs = 10.8.0.3/32\n"
}

func TestIPv6MigrationPlanPreservesIdentityAndIsIdempotent(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n"} {
		original := strings.ReplaceAll(migrationConfig(), "\n", ending)
		plan, err := planIPv6Config([]byte(original), "fd77::1/64")
		if err != nil {
			t.Fatal(err)
		}
		expected := strings.Replace(original, "10.8.0.1/24 #", "10.8.0.1/24, fd77::1/64 #", 1)
		expected = strings.Replace(expected, "10.8.0.2/32 #", "10.8.0.2/32, fd77::1:a08:2/128 #", 1)
		expected = strings.Replace(expected, "10.8.0.3/32"+ending, "10.8.0.3/32, fd77::1:a08:3/128"+ending, 1)
		if string(plan.Config) != expected {
			t.Fatalf("unrelated configuration changed: %q", plan.Config)
		}
		if len(plan.Assignments) != 2 || plan.Assignments[testKey('A')] != "fd77::1:a08:2" || plan.Assignments[testKey('B')] != "fd77::1:a08:3" {
			t.Fatal("incorrect key-bound assignment", plan.Assignments)
		}
		again, err := planIPv6Config(plan.Config, "fd77::1/64")
		if err != nil || !bytes.Equal(again.Config, plan.Config) {
			t.Fatal("migration is not idempotent", err)
		}
	}
}

func TestIPv6MigrationPlanKeepsExistingPeerAddress(t *testing.T) {
	original := strings.Replace(migrationConfig(), "AllowedIPs = 10.8.0.3/32", "AllowedIPs = 10.8.0.3/32, fd77::b/128", 1)
	plan, err := planIPv6Config([]byte(original), "fd77::1/64")
	if err != nil || plan.Assignments[testKey('B')] != "fd77::b" {
		t.Fatal("existing address changed", err)
	}
	if !strings.Contains(string(plan.Config), "AllowedIPs = 10.8.0.3/32, fd77::b/128\n") {
		t.Fatal("existing peer configuration changed")
	}
}

func TestIPv6MigrationPlanRejectsAmbiguousInputWithoutPlan(t *testing.T) {
	original := migrationConfig()
	invalid := []string{
		strings.Replace(original, testKey('B'), testKey('A'), 1),
		strings.Replace(original, "10.8.0.3/32", "10.8.0.2/32", 1),
		strings.Replace(original, "10.8.0.2/32", "10.8.0.0/24", 1),
		strings.Replace(original, "10.8.0.2/32", "10.8.0.2/32, 10.8.0.9/32", 1),
		strings.Replace(original, "10.8.0.3/32", "10.8.0.3/32, fd77::1:a08:2/128", 1),
		strings.Replace(original, "10.8.0.2/32", "10.8.0.2/32, fd77::1/128", 1),
		strings.Replace(original, "10.8.0.2/32", "10.8.0.2/32, fd88::2/128", 1),
		strings.Replace(original, "10.8.0.2/32", "10.8.0.2/32, fd77::/64", 1),
		strings.Replace(original, "10.8.0.1/24", "10.8.0.1/24, fd88::1/64", 1),
		strings.Replace(original, "10.8.0.1/24", "10.8.0.1/24, fd77::2/64", 1),
		strings.Replace(original, "PublicKey = "+testKey('A'), "PublicKey = invalid", 1),
		strings.Replace(original, "[Peer]", "[Unknown]", 1),
		original + "[Interface]\nAddress = fd77::1/64\n",
		strings.Replace(original, "Address = 10.8.0.1/24 # local interface\n", "", 1),
		strings.Replace(original, "PresharedKey = preserve-psk-A", "PublicKey = "+testKey('B'), 1),
		original + "\x00", string([]byte{0xff, 0xfe}), "", strings.Repeat("x", (4<<20)+1),
	}
	for index, text := range invalid {
		input := []byte(text)
		before := bytes.Clone(input)
		plan, err := planIPv6Config(input, "fd77::1/64")
		if err == nil || plan.Config != nil || plan.Assignments != nil || !bytes.Equal(input, before) {
			t.Fatalf("invalid case %d produced a plan or modified source", index)
		}
	}
	for _, server := range []string{"10.8.0.1/24", "::1/64", "fe80::1/64", "ff02::1/64", "fd77::1/128", "FD77::1/64", "fd77::1/64\n", "::ffff:10.8.0.1/64"} {
		if _, err := planIPv6Config([]byte(original), server); err == nil {
			t.Fatal("invalid server accepted", server)
		}
	}
}
