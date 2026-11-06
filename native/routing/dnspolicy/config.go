// Package dnspolicy defines per-domain DNS independently of application/IP routing.
package dnspolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/StannisMod/amnezia-client/native/routing/rules"
)

type Resolver struct {
	networkTLSOpportunistic bool
	Source                  string       `json:"source,omitempty"`
	Interface               string       `json:"interface,omitempty"`
	Name                    string       `json:"name,omitempty"`
	Transport               string       `json:"transport"`
	Server                  string       `json:"server"`
	Port                    uint16       `json:"port,omitempty"`
	Path                    rules.Action `json:"path"`
	// A named upstream must have an explicit numeric bootstrap on the SAME path.
	Bootstrap  netip.AddrPort `json:"bootstrap,omitempty"`
	ServerName string         `json:"server_name,omitempty"`
	HTTPSPath  string         `json:"https_path,omitempty"`
}

type Rule struct {
	Kind     rules.Kind `json:"kind"`
	Value    string     `json:"value"`
	Policy   string     `json:"policy"`
	Disabled bool       `json:"disabled,omitempty"`
}

type Config struct {
	PreserveNetworkDomains bool                `json:"preserve_network_domains,omitempty"`
	NetworkRules           []Rule              `json:"network_rules,omitempty"`
	Version                int                 `json:"version"`
	Default                string              `json:"default"`
	FollowRouting          bool                `json:"follow_routing"`
	Direct                 string              `json:"direct,omitempty"`
	VPN                    string              `json:"vpn,omitempty"`
	Policies               map[string]Resolver `json:"policies"`
	Rules                  []Rule              `json:"rules"`
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type plain Config
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return errors.New("invalid or unsupported split DNS configuration")
	}
	*c = Config(decoded)
	return nil
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// CheckAddress rejects our managed resolver/FakeIP pools and unusable upstreams.
// A loopback DNS is permitted only on DIRECT; OS stubs need native preparation.
func CheckAddress(a netip.Addr, path rules.Action) error {
	a = a.Unmap()
	if a.Zone() != "" {
		if !a.IsLinkLocalUnicast() {
			return errors.New("only link-local DNS addresses may have a scope")
		}
		a = a.WithZone("")
	}
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() ||
		netip.MustParsePrefix("198.18.0.0/15").Contains(a) || netip.MustParsePrefix("fc00::/18").Contains(a) ||
		netip.MustParsePrefix("172.19.0.0/30").Contains(a) || netip.MustParsePrefix("fdfe:dcba:9876::/126").Contains(a) {
		return errors.New("DNS upstream is not a usable address or points at managed DNS")
	}
	if a.IsLoopback() && path != rules.Direct {
		return errors.New("a local DNS resolver requires DIRECT")
	}
	if a == netip.MustParseAddr("127.0.0.53") || a == netip.MustParseAddr("127.0.0.54") {
		return errors.New("system DNS stub requires a native upstream; select a numeric DNS server")
	}
	return nil
}

func (c Config) Normalize(route rules.Config) (Config, error) {
	if c.Version != 1 {
		return Config{}, errors.New("unsupported split DNS schema version")
	}
	if len(c.Policies) == 0 || len(c.Policies) > 64 || len(c.Rules) > 4096 {
		return Config{}, errors.New("split DNS policy limit exceeded")
	}
	n := c
	n.Policies = make(map[string]Resolver, len(c.Policies))
	n.Rules = nil
	for id, p := range c.Policies {
		if !validID(id) {
			return Config{}, errors.New("invalid DNS policy identifier")
		}
		if p.Path != rules.Direct && p.Path != rules.VPN {
			return Config{}, errors.New("DNS policy path must be explicit")
		}
		if p.Interface != "" && (p.Path != rules.Direct || len(p.Interface) > 128 || strings.ContainsAny(p.Interface, "/\\\t\r\n\x00") || strings.EqualFold(p.Interface, "amnrouting0") || strings.EqualFold(p.Interface, "AmneziaDomainRouting")) {
			return Config{}, errors.New("invalid DNS interface binding")
		}
		if p.Source != "" {
			if p.Source != "network" || p.Path != rules.Direct || (p.Transport != "udp" && p.Transport != "tcp") || p.Server != "" || p.Bootstrap.IsValid() || p.ServerName != "" || p.HTTPSPath != "" {
				return Config{}, errors.New("network DNS source requires plain DIRECT DNS without an explicit server")
			}
			n.Policies[id] = p
			continue
		}
		switch p.Transport {
		case "udp", "tcp":
			if p.Port == 0 {
				p.Port = 53
			}
		case "tls":
			if p.Port == 0 {
				p.Port = 853
			}
		case "https":
			if p.Port == 0 {
				p.Port = 443
			}
			if p.HTTPSPath == "" {
				p.HTTPSPath = "/dns-query"
			}
		default:
			return Config{}, errors.New("unsupported DNS transport")
		}
		if p.HTTPSPath != "" && (p.Transport != "https" || !strings.HasPrefix(p.HTTPSPath, "/") || strings.ContainsAny(p.HTTPSPath, "\r\n#")) {
			return Config{}, errors.New("invalid DNS HTTPS path")
		}
		if p.ServerName != "" {
			var err error
			p.ServerName, err = rules.NormalizeDomain(p.ServerName)
			if err != nil || (p.Transport != "tls" && p.Transport != "https") {
				return Config{}, errors.New("invalid DNS TLS server name")
			}
		}
		if a, err := netip.ParseAddr(p.Server); err == nil {
			if err = CheckAddress(a, p.Path); err != nil {
				return Config{}, err
			}
			p.Server = a.String()
			if p.Bootstrap.IsValid() {
				return Config{}, errors.New("numeric DNS upstream does not need bootstrap")
			}
		} else {
			p.Server, err = rules.NormalizeDomain(p.Server)
			if err != nil {
				return Config{}, errors.New("invalid DNS upstream name")
			}
			if !p.Bootstrap.IsValid() || p.Bootstrap.Port() == 0 {
				return Config{}, errors.New("named DNS upstream requires numeric bootstrap on its policy path")
			}
			if err = CheckAddress(p.Bootstrap.Addr(), p.Path); err != nil {
				return Config{}, err
			}
		}
		n.Policies[id] = p
	}
	has := func(id string) bool { _, ok := n.Policies[id]; return ok }
	if !c.FollowRouting && !has(c.Default) {
		return Config{}, errors.New("default DNS policy does not exist")
	}
	if c.FollowRouting {
		if !has(c.Direct) || !has(c.VPN) || n.Policies[c.Direct].Path != rules.Direct || n.Policies[c.VPN].Path != rules.VPN {
			return Config{}, errors.New("DNS by site route requires a DIRECT and a VPN policy")
		}
		if _, err := route.Normalize(); err != nil {
			return Config{}, err
		}
	}
	seen := make(map[string]string)
	for i, r := range c.Rules {
		if !has(r.Policy) || (r.Kind != rules.Domain && r.Kind != rules.Suffix) {
			return Config{}, fmt.Errorf("DNS rule %d: invalid policy or match kind", i+1)
		}
		if strings.HasPrefix(r.Value, "*.") {
			r.Kind = rules.Suffix
			r.Value = strings.TrimPrefix(r.Value, "*.")
		}
		var err error
		r.Value, err = rules.NormalizeDomain(r.Value)
		if err != nil {
			return Config{}, fmt.Errorf("DNS rule %d: invalid domain", i+1)
		}
		if !r.Disabled {
			key := string(r.Kind) + ":" + r.Value
			if previous, ok := seen[key]; ok {
				if previous != r.Policy {
					return Config{}, fmt.Errorf("DNS rule %d: conflicting duplicate", i+1)
				}
				continue
			}
			seen[key] = r.Policy
		}
		n.Rules = append(n.Rules, r)
	}
	sort.SliceStable(n.Rules, func(i, j int) bool {
		a, b := n.Rules[i], n.Rules[j]
		if a.Kind != b.Kind {
			return a.Kind == rules.Domain
		}
		return strings.Count(a.Value, ".") > strings.Count(b.Value, ".")
	})
	if len(c.NetworkRules) > 0 {
		system := c
		system.Rules = c.NetworkRules
		system.NetworkRules = nil
		normalized, err := system.Normalize(route)
		if err != nil {
			return Config{}, err
		}
		n.NetworkRules = normalized.Rules
	}
	return n, nil
}

func Tag(id string) string { return "dns-policy-" + id }

func (c Config) NeedsNetwork() bool {
	if c.PreserveNetworkDomains {
		return true
	}
	for _, p := range c.Policies {
		if p.Source == "network" {
			return true
		}
	}
	return false
}

func (c Config) InterfaceOutbounds() []any {
	var result []any
	ids := make([]string, 0, len(c.Policies))
	for id := range c.Policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if p := c.Policies[id]; p.Interface != "" {
			result = append(result, map[string]any{"type": "direct", "tag": "dns-direct-" + id, "interface": p.Interface})
		}
	}
	return result
}

// Compile emits only validated DNS transports and name rules. The first rule
// supplies FakeIP to captured A/AAAA; real internal lookups skip FakeIP.
func (c Config) Compile(route rules.Config, capture string) (map[string]any, error) {
	n, err := c.Normalize(route)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(n.Policies))
	for id := range n.Policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	servers := []any{map[string]any{"type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}}
	for _, id := range ids {
		p := n.Policies[id]
		if p.Source != "" {
			return nil, errors.New("network DNS source must be prepared by the native host before capture")
		}
		var detour any = p.Path
		if p.Interface != "" {
			detour = "dns-direct-" + id
		}
		s := map[string]any{"type": p.Transport, "tag": Tag(id), "server": p.Server, "server_port": p.Port, "detour": detour}
		if p.Bootstrap.IsValid() {
			bootstrap := "dns-bootstrap-" + id
			servers = append(servers, map[string]any{"type": "udp", "tag": bootstrap, "server": p.Bootstrap.Addr().String(), "server_port": p.Bootstrap.Port(), "detour": detour})
			s["domain_resolver"] = bootstrap
		}
		if p.Transport == "tls" || p.Transport == "https" {
			tls := map[string]any{"enabled": true}
			if p.networkTLSOpportunistic {
				tls["insecure"] = true
			}
			if p.ServerName != "" {
				tls["server_name"] = p.ServerName
			}
			s["tls"] = tls
		}
		if p.Transport == "https" {
			s["path"] = p.HTTPSPath
		}
		servers = append(servers, s)
	}
	entries := []any{map[string]any{"inbound": []string{capture}, "query_type": []string{"A", "AAAA"}, "action": "route", "server": "fake"}}
	appendRule := func(kind rules.Kind, name, id string) {
		key := "domain"
		if kind == rules.Suffix {
			key = "domain_suffix"
		}
		entries = append(entries, map[string]any{key: []string{name}, "action": "route", "server": Tag(id)})
	}
	for _, r := range n.Rules {
		if !r.Disabled {
			appendRule(r.Kind, r.Value, r.Policy)
		}
	}
	for _, r := range n.NetworkRules {
		if !r.Disabled {
			appendRule(r.Kind, r.Value, r.Policy)
		}
	}
	final := n.Default
	if n.FollowRouting {
		routing, _ := route.Normalize()
		for _, r := range routing.Rules {
			// DNS lookups have no destination flow port or network. Only
			// unconditional name rules can select a resolver; Block uses
			// VPN DNS and is enforced later by the connection router.
			if r.Disabled || r.Kind == rules.CIDR || r.Network != "" || r.Ports != "" {
				continue
			}
			id := n.VPN
			if r.Action == rules.Direct {
				id = n.Direct
			}
			appendRule(r.Kind, r.Value, id)
		}
		final = n.VPN
		if routing.Default == rules.Direct {
			final = n.Direct
		}
	}
	return map[string]any{"servers": servers, "rules": entries, "final": Tag(final), "reverse_mapping": false}, nil
}
