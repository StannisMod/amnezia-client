package desktop

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func testProfile(t *testing.T) map[string]any {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"protocol": "awg", "dns1": "1.1.1.1", "sing_box_dns_path": "vpn",
		"sing_box_routing": map[string]any{"version": 1, "default": "vpn", "rules": []any{map[string]any{"kind": "suffix", "value": "*.ru", "action": "direct"}}},
		"splitTunnelSites": []string{"203.0.113.234"},
		"awg_config_data":  map[string]any{"client_ip": "10.77.0.1/32, fd77::1/128", "client_priv_key": base64.StdEncoding.EncodeToString(private.Bytes()), "server_pub_key": base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()), "hostName": "192.0.2.10", "port": 51820, "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "mtu": "1280", "Jc": "3", "Jmin": "40", "Jmax": "80", "S1": "16", "S2": "24", "H1": "1001", "H2": "1002", "H3": "1003", "H4": "1004", "HeaderProtectionKey": base64.StdEncoding.EncodeToString(make([]byte, 32)), "RandomTrailers": "on", "DisableCookies": "off"},
	}
}

func TestNativeAWGProfilePreservesParametersAndDomainRules(t *testing.T) {
	profile := testProfile(t)
	raw, _ := json.Marshal(profile)
	config, err := ProfileSession(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.AWG.Address) != 2 || config.AWG.MTU != 1280 || config.AWG.Parameters["jc"] != "3" || config.AWG.Parameters["random_trailers"] != "true" || config.AWG.Parameters["disable_cookies"] != "false" || config.AWG.Parameters["header_protection_key"] != strings.Repeat("0", 64) {
		t.Fatal("AWG profile semantics changed")
	}
	compiled, err := config.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(compiled), "203.0.113.234") {
		t.Fatal("legacy cached IP exclusions reached the domain engine")
	}
	if config.Rules.Rules[0].Value != "*.ru" {
		t.Fatal("domain identity was lost")
	}
}

func TestRejectUnsupportedDesktopPoliciesAndInvalidAWG(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { p["appSplitTunnelType"] = 1 },
		func(p map[string]any) { p["appSplitTunnelType"] = 3 },
		func(p map[string]any) { p["appSplitTunnelType"] = 2; p["splitTunnelApps"] = []string{"relative.exe"} },
		func(p map[string]any) { p["protocol"] = "wireguard" },
		func(p map[string]any) { p["awg_config_data"].(map[string]any)["hostName"] = "bootstrap.invalid" },
		func(p map[string]any) { p["awg_config_data"].(map[string]any)["port"] = 70000 },
		func(p map[string]any) { p["awg_config_data"].(map[string]any)["allowed_ips"] = []string{"10.0.0.0/8"} },
		func(p map[string]any) { p["awg_config_data"].(map[string]any)["RandomTrailers"] = "maybe" },
		func(p map[string]any) { p["awg_config_data"].(map[string]any)["HeaderProtectionKey"] = "invalid" },
	} {
		profile := testProfile(t)
		mutate(profile)
		raw, _ := json.Marshal(profile)
		if _, err := ProfileSession(raw); err == nil {
			t.Fatal("accepted an unsupported policy or malformed profile")
		}
	}
}

func TestDesktopApplicationScopeUsesExecutableIdentity(t *testing.T) {
	for _, mode := range []int{1, 2} {
		profile := testProfile(t)
		profile["appSplitTunnelType"] = mode
		path := filepath.Join(t.TempDir(), "app.[x]")
		profile["splitTunnelApps"] = []string{path}
		raw, _ := json.Marshal(profile)
		config, err := ProfileSession(raw)
		if err != nil {
			t.Fatal(err)
		}
		want := "include"
		if mode == 2 {
			want = "exclude"
		}
		if config.Applications == nil || config.Applications.Mode != want || config.Applications.Paths[0] != path {
			t.Fatal("application scope lost during profile conversion")
		}
	}
}
