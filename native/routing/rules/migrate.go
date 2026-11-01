package rules

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
)

// FromLegacy imports the site's key, not its cached DNS addresses. A domain
// resolved on a previous connection must not turn into an IP/CIDR exclusion.
// The caller retains the original profile unchanged, including credentials,
// AWG options, app exclusions and unrelated protocol data.
// Modes match client/core/utils/routeModes.h.
func FromLegacy(enabled bool, mode int, sites map[string][]string) (Config, error) {
	c := Config{Version: 1, Default: VPN}
	if !enabled || mode == 0 {
		return c, nil
	}
	if mode != 1 && mode != 2 {
		return Config{}, errors.New("unsupported legacy route mode")
	}
	action := Direct
	if mode == 1 {
		c.Default = Direct
		action = VPN
	}
	keys := make([]string, 0, len(sites))
	for key := range sites {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		kind := Domain
		if _, e := netip.ParsePrefix(key); e == nil {
			kind = CIDR
		} else if _, e := netip.ParseAddr(key); e == nil {
			kind = CIDR
		} else if strings.HasPrefix(key, "*.") {
			kind = Suffix
		}
		c.Rules = append(c.Rules, Rule{Kind: kind, Value: key, Action: action})
	}
	return c.Normalize()
}
