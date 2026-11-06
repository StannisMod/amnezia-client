package dnspolicy

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/StannisMod/amnezia-client/native/routing/rules"
)

func fixture() (Config, rules.Config) {
	return Config{Version: 1, Default: "tunnel", FollowRouting: true, Direct: "lan", VPN: "tunnel",
			Policies: map[string]Resolver{"lan": {Transport: "udp", Server: "192.168.0.1", Path: rules.Direct}, "tunnel": {Transport: "udp", Server: "1.1.1.1", Path: rules.VPN}},
			Rules:    []Rule{{Kind: rules.Suffix, Value: "*.Corp.Example.", Policy: "lan"}, {Kind: rules.Domain, Value: "public.corp.example", Policy: "tunnel"}}},
		rules.Config{Version: 1, Default: rules.VPN, Rules: []rules.Rule{{Kind: rules.Suffix, Value: "*.ru", Action: rules.Direct}, {Kind: rules.CIDR, Value: "192.168.0.0/16", Action: rules.Direct}}}
}

func TestCompilePrecedenceAndSiteRouting(t *testing.T) {
	c, r := fixture()
	got, err := c.Compile(r, "tun")
	if err != nil {
		t.Fatal(err)
	}
	entries := got["rules"].([]any)
	if len(entries) != 4 {
		t.Fatalf("unexpected rules: %#v", entries)
	}
	if entries[1].(map[string]any)["domain"].([]string)[0] != "public.corp.example" || entries[2].(map[string]any)["domain_suffix"].([]string)[0] != "corp.example" {
		t.Fatal("lost exact-over-suffix precedence")
	}
	if entries[3].(map[string]any)["server"] != Tag("lan") || got["final"] != Tag("tunnel") {
		t.Fatal("lost site-route DNS mapping")
	}
	r.Default = rules.Direct
	got, err = c.Compile(r, "tun")
	if err != nil || got["final"] != Tag("lan") {
		t.Fatal("inverse routing default", err)
	}
	c.FollowRouting = false
	got, err = c.Compile(r, "tun")
	if err != nil || len(got["rules"].([]any)) != 3 || got["final"] != Tag("tunnel") {
		t.Fatal("explicit DNS was changed by site routes", err)
	}
}

func TestInvalidPoliciesFailClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"version", func(c *Config) { c.Version = 2 }},
		{"default", func(c *Config) { c.FollowRouting = false; c.Default = "missing" }},
		{"path", func(c *Config) { p := c.Policies["lan"]; p.Path = rules.VPN; c.Policies["lan"] = p }},
		{"duplicate", func(c *Config) {
			c.Rules = append(c.Rules, Rule{Kind: rules.Suffix, Value: "corp.example", Policy: "tunnel"})
		}},
		{"managed", func(c *Config) { p := c.Policies["lan"]; p.Server = "172.19.0.2"; c.Policies["lan"] = p }},
		{"fakeip", func(c *Config) { p := c.Policies["lan"]; p.Server = "198.18.0.1"; c.Policies["lan"] = p }},
		{"mapped-fakeip", func(c *Config) { p := c.Policies["lan"]; p.Server = "::ffff:198.18.0.1"; c.Policies["lan"] = p }},
		{"system-stub", func(c *Config) { p := c.Policies["lan"]; p.Server = "127.0.0.53"; c.Policies["lan"] = p }},
		{"bootstrap-cycle", func(c *Config) { p := c.Policies["tunnel"]; p.Server = "dns.example"; c.Policies["tunnel"] = p }},
		{"bootstrap-managed", func(c *Config) {
			p := c.Policies["tunnel"]
			p.Server = "dns.example"
			p.Bootstrap = netip.MustParseAddrPort("172.19.0.2:53")
			c.Policies["tunnel"] = p
		}},
		{"cidr", func(c *Config) {
			c.Rules = append(c.Rules, Rule{Kind: rules.CIDR, Value: "192.168.0.0/16", Policy: "lan"})
		}},
		{"disabled-invalid", func(c *Config) {
			c.Rules = append(c.Rules, Rule{Kind: rules.Domain, Value: "bad..example", Policy: "lan", Disabled: true})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, r := fixture()
			test.mutate(&c)
			if _, err := c.Compile(r, "tun"); err == nil {
				t.Fatal("accepted unsafe/ambiguous policy")
			}
		})
	}
}

func TestNamedEncryptedUpstreamHasExplicitBootstrap(t *testing.T) {
	c, r := fixture()
	c.Policies["tunnel"] = Resolver{Transport: "https", Server: "DNS.Example.", Path: rules.VPN, Bootstrap: netip.MustParseAddrPort("9.9.9.9:53")}
	got, err := c.Compile(r, "tun")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(got)
	var parsed map[string]any
	if err = json.Unmarshal(encoded, &parsed); err != nil {
		t.Fatal(err)
	}
	servers := got["servers"].([]any)
	bootstrap := servers[2].(map[string]any)
	upstream := servers[3].(map[string]any)
	if bootstrap["detour"] != rules.VPN || upstream["domain_resolver"] != "dns-bootstrap-tunnel" || upstream["server"] != "dns.example" || upstream["path"] != "/dns-query" {
		t.Fatal("unsafe hostname bootstrap", string(encoded))
	}
}

func TestUnsupportedDNSFieldsAreNotSilentlyIgnored(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"fallback":"system"}`,
		`{"version":1,"policies":{"vpn":{"transport":"udp","server":"1.1.1.1","path":"vpn","fallback":"direct"}}}`,
		`{"version":1,"rules":[{"kind":"domain","value":"test.example","policy":"vpn","application":"browser"}]}`,
	} {
		var c Config
		if err := json.Unmarshal([]byte(raw), &c); err == nil {
			t.Fatal("ignored unsupported DNS behavior", raw)
		}
	}
}
