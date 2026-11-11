package engine

import (
	"errors"
	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
)

// AndroidApplications contains a connection-time package-to-UID snapshot.
// Only these UIDs may consult destination rules. Every other captured flow,
// including unknown ownership, remains VPN-only. Native VpnService owns DIRECT
// application exclusion; it must not be emulated with protected proxy sockets.
type AndroidApplications struct {
	Live          bool     `json:"live,omitempty"`
	SiteRulesUIDs []uint32 `json:"site_rules_uids"`
	VPNDNSPolicy  string   `json:"vpn_dns_policy,omitempty"`
}

// FakeIP answers are shared safely across Android's system resolver cache.
// Actual name resolution selects a transport using the connection's UID;
// independent caches prevent a site-rule resolver answer from crossing into
// the always-VPN resolver context.
func (a *AndroidApplications) applyDNS(settings map[string]any, config *dnspolicy.Config, resolverAction rules.Action) error {
	if a == nil {
		return nil
	}
	server := "upstream"
	if config == nil {
		if resolverAction != rules.VPN {
			return errors.New("Android always-VPN applications require VPN DNS")
		}
		if a.VPNDNSPolicy != "" {
			return errors.New("Android VPN DNS policy requires split DNS configuration")
		}
	} else {
		id := a.VPNDNSPolicy
		if id == "" {
			id = config.VPN
		}
		policy, ok := config.Policies[id]
		if !ok || policy.Path != rules.VPN || policy.Source != "" {
			return errors.New("Android always-VPN DNS policy must select a VPN resolver")
		}
		server = dnspolicy.Tag(id)
	}
	entries, ok := settings["rules"].([]any)
	if !ok || len(entries) == 0 {
		return errors.New("missing Android FakeIP DNS capture")
	}
	override := map[string]any{"action": "route", "server": server}
	if len(a.SiteRulesUIDs) > 0 {
		override["user_id"] = a.SiteRulesUIDs
		override["invert"] = true
	}
	// The capture rule remains first; the DNS-only generation removes it.
	settings["rules"] = append([]any{entries[0], override}, entries[1:]...)
	settings["independent_cache"] = true
	return nil
}

func (a *AndroidApplications) compile() ([]any, error) {
	if a == nil {
		return nil, nil
	}
	if len(a.SiteRulesUIDs) > 4096 {
		return nil, errors.New("too many Android application UIDs")
	}
	seen := make(map[uint32]bool, len(a.SiteRulesUIDs))
	for _, uid := range a.SiteRulesUIDs {
		if uid == 0 || uid > 2147483647 || seen[uid] {
			return nil, errors.New("invalid or duplicate Android application UID")
		}
		seen[uid] = true
	}
	if len(a.SiteRulesUIDs) == 0 {
		return []any{map[string]any{"action": "route", "outbound": "vpn"}}, nil
	}
	return []any{map[string]any{"user_id": a.SiteRulesUIDs, "invert": true, "action": "route", "outbound": "vpn"}}, nil
}
