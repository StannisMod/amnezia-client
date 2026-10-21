package engine

import (
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
)

const TUNTag = "amnezia-tun"

// SessionConfig contains no OS route instructions. A native host must create
// and protect its capture boundary before starting the engine, and restore
// routes/resolvers after stopping it. The host installs its PlatformInterface
// to provide the existing VPN descriptor on mobile.
type SessionConfig struct {
	Rules          rules.Config      `json:"rules"`
	AWG            awg.Config        `json:"awg"`
	Resolver       netip.AddrPort    `json:"resolver"`
	ResolverAction rules.Action      `json:"resolver_action"`
	Applications   *ApplicationScope `json:"applications,omitempty"`
}

func (c SessionConfig) Compile() ([]byte, error) {
	if !c.Resolver.IsValid() || c.Resolver.Port() == 0 {
		return nil, errors.New("numeric DNS resolver is required")
	}
	if c.ResolverAction != rules.Direct && c.ResolverAction != rules.VPN {
		return nil, errors.New("DNS resolver path must be explicit")
	}
	if c.ResolverAction == rules.VPN && c.Resolver.Addr().IsLoopback() {
		return nil, errors.New("a local DNS stub requires the native DIRECT path")
	}
	compiled, e := c.Rules.Compile()
	if e != nil {
		return nil, e
	}
	var route map[string]any
	if e = json.Unmarshal(compiled, &route); e != nil {
		return nil, e
	}
	route["default_domain_resolver"] = "upstream"
	userRules := route["rules"].([]any)
	scopeRules, e := c.Applications.compile()
	if e != nil {
		return nil, e
	}
	route["rules"] = append(append([]any{map[string]any{"inbound": []string{TUNTag}, "port": 53, "action": "hijack-dns"}}, scopeRules...), userRules...)
	awgBytes, e := json.Marshal(c.AWG)
	if e != nil {
		return nil, errors.New("invalid AWG configuration")
	}
	var vpn map[string]any
	json.Unmarshal(awgBytes, &vpn)
	vpn["type"] = awg.Type
	vpn["tag"] = "vpn"
	config := map[string]any{
		"log":       map[string]any{"disabled": true},
		"inbounds":  []any{map[string]any{"type": "tun", "tag": TUNTag, "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 1280, "stack": "gvisor", "auto_route": false}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}, vpn},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "udp", "tag": "upstream", "server": c.Resolver.Addr().String(), "server_port": c.Resolver.Port(), "detour": c.ResolverAction},
				map[string]any{"type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"},
			},
			"rules": []any{map[string]any{"inbound": []string{TUNTag}, "query_type": []string{"A", "AAAA"}, "action": "route", "server": "fake"}},
			"final": "upstream", "reverse_mapping": false,
		},
		"route": route,
	}
	return json.Marshal(config)
}
