package engine

import "errors"

// AndroidApplications contains a connection-time package-to-UID snapshot.
// Only these UIDs may consult destination rules. Every other captured flow,
// including unknown ownership, remains VPN-only. Native VpnService owns DIRECT
// application exclusion; it must not be emulated with protected proxy sockets.
type AndroidApplications struct {
	SiteRulesUIDs []uint32 `json:"site_rules_uids"`
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
