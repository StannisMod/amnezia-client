package engine

import (
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
)

const TUNTag = "amnezia-tun"

// RoutingConfig is independent of the VPN transport. Native hosts still own
// capture/protection and supply a separately validated transport adapter.
type RoutingConfig struct {
	Rules          rules.Config
	Resolver       netip.AddrPort
	ResolverAction rules.Action
	Applications   *ApplicationScope
	DNS            *dnspolicy.Config
}

// compile is internal: hosts cannot inject an arbitrary raw sing-box outbound.
func (c RoutingConfig) compile(vpn map[string]any) ([]byte, error) {
	if c.DNS == nil {
		if !c.Resolver.IsValid() || c.Resolver.Port() == 0 {
			return nil, errors.New("numeric DNS resolver is required")
		}
		if c.ResolverAction != rules.Direct && c.ResolverAction != rules.VPN {
			return nil, errors.New("DNS resolver path must be explicit")
		}
		if c.ResolverAction == rules.VPN && c.Resolver.Addr().IsLoopback() {
			return nil, errors.New("a local DNS stub requires the native DIRECT path")
		}
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
	preRules := append([]any{map[string]any{"inbound": []string{TUNTag}, "port": 53, "action": "hijack-dns"}}, scopeRules...)
	// FakeIP and explicit domain identities remain authoritative. Sniff only
	// IP-literal flows (e.g. browser DoH), without rewriting their destination.
	preRules = append(preRules, map[string]any{"type": "logical", "mode": "and", "rules": []any{
		map[string]any{"inbound": []string{TUNTag}}, map[string]any{"domain_regex": []string{".+"}, "invert": true}},
		"action": "sniff", "sniffer": []string{"http", "tls", "quic"}, "timeout": "300ms"})
	route["rules"] = append(preRules, userRules...)
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
	if c.DNS != nil {
		dns, err := c.DNS.Compile(c.Rules, TUNTag)
		if err != nil {
			return nil, err
		}
		config["dns"] = dns
		config["outbounds"] = append(config["outbounds"].([]any), c.DNS.InterfaceOutbounds()...)
		// A fixed default_domain_resolver bypasses per-domain DNS rules in
		// sing-box dialers. Our outbounds use DNSRouter.Lookup without pinning.
		delete(route, "default_domain_resolver")
	}
	return json.Marshal(config)
}
