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
	Rules               rules.Config
	Resolver            netip.AddrPort
	ResolverAction      rules.Action
	Applications        *ApplicationScope
	AndroidApplications *AndroidApplications
	DNS                 *dnspolicy.Config
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
	// Domain rules run first. CIDR rules must see real DNS addresses rather
	// than the synthetic address returned to a captured application.
	evaluated := make([]any, 0, len(userRules)+1)
	resolved := false
	for _, value := range userRules {
		item := value.(map[string]any)
		if _, ok := item["ip_cidr"]; ok && !resolved {
			evaluated = append(evaluated, map[string]any{"action": "resolve"})
			resolved = true
		}
		evaluated = append(evaluated, item)
	}
	userRules = evaluated
	scopeRules, e := c.Applications.compile()
	if e != nil {
		return nil, e
	}
	preRules := append([]any{map[string]any{"inbound": []string{TUNTag}, "port": 53, "action": "hijack-dns"}}, scopeRules...)
	if c.Applications != nil && c.AndroidApplications != nil {
		return nil, errors.New("desktop and Android application policies cannot be combined")
	}
	appRules, e := c.AndroidApplications.compile()
	if e != nil {
		return nil, e
	}
	var liveOffsets []int
	liveApps := c.AndroidApplications != nil && c.AndroidApplications.Live
	if liveApps {
		route["find_process"] = true
		appRules = []any{map[string]any{"action": "route", "outbound": "vpn"}}
	}
	if len(appRules) != 0 {
		// Preserve the destination rule order, including explicit rejects.
		// For always-VPN UIDs only, replace each matching DIRECT decision
		// with VPN. An early unconditional VPN rule would bypass blocks.
		var scoped []any
		for _, value := range userRules {
			item := value.(map[string]any)
			if item["action"] == "route" && item["outbound"] == "direct" {
				condition := make(map[string]any)
				for key, value := range item {
					if key != "action" && key != "outbound" {
						condition[key] = value
					}
				}
				override := map[string]any{"type": "logical", "mode": "and", "rules": []any{condition}, "action": "route", "outbound": "vpn"}
				if !liveApps && len(c.AndroidApplications.SiteRulesUIDs) != 0 {
					override["rules"] = []any{condition, map[string]any{"user_id": c.AndroidApplications.SiteRulesUIDs, "invert": true}}
				}
				if liveApps {
					liveOffsets = append(liveOffsets, len(scoped))
				}
				scoped = append(scoped, override)
			}
			scoped = append(scoped, item)
		}
		if liveApps {
			liveOffsets = append(liveOffsets, len(scoped))
		}
		userRules = append(scoped, appRules...)
	}
	// Optional domain policies need visible Host/SNI for IP-literal flows.
	// Ordinary all-VPN/application-only sessions must not pay the inspection
	// delay (notably for server-first protocols) when no name rule can use it.
	needsNames := false
	for _, rule := range c.Rules.Rules {
		if !rule.Disabled && (rule.Kind == rules.Domain || rule.Kind == rules.Suffix) {
			needsNames = true
			break
		}
	}
	if needsNames {
		preRules = append(preRules, map[string]any{"type": "logical", "mode": "and", "rules": []any{
			map[string]any{"inbound": []string{TUNTag}}, map[string]any{"domain_regex": []string{".+"}, "invert": true}},
			"action": "sniff", "sniffer": []string{"http", "tls", "quic"}, "timeout": "300ms"})
	}

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
	if err := c.AndroidApplications.applyDNS(config["dns"].(map[string]any), c.DNS, c.ResolverAction); err != nil {
		return nil, err
	}
	if liveApps {
		for i := range liveOffsets {
			liveOffsets[i] += len(preRules)
		}
		config[liveAndroidPolicyKey] = liveAndroidPolicyOptions{Applications: *c.AndroidApplications, Rules: liveOffsets}
	}
	return json.Marshal(config)
}
