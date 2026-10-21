// Package rules defines the platform-neutral routing configuration. It never
// resolves hostnames into persistent IP rules.
package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

type Action string

const (
	Direct Action = "direct"
	VPN    Action = "vpn"
)

type Kind string

const (
	Domain Kind = "domain"
	Suffix Kind = "suffix"
	CIDR   Kind = "cidr"
)

type Rule struct {
	Kind     Kind   `json:"kind"`
	Value    string `json:"value"`
	Action   Action `json:"action"`
	Disabled bool   `json:"disabled,omitempty"`
}
type Config struct {
	Version int    `json:"version"`
	Default Action `json:"default"`
	Rules   []Rule `json:"rules"`
}

func validAction(a Action) bool { return a == Direct || a == VPN }

func NormalizeDomain(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || strings.ContainsAny(s, "*:/\\@ \t\r\n") {
		return "", errors.New("expected a domain name")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", errors.New("IP literals require an IP/CIDR rule")
	}
	a, err := idna.Lookup.ToASCII(s)
	if err != nil || len(a) > 253 {
		return "", errors.New("invalid international domain name")
	}
	for _, label := range strings.Split(a, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("invalid DNS label character")
			}
		}
	}
	return a, nil
}

// Normalize validates disabled rules too: re-enabling a saved rule must not
// silently introduce a different interpretation on another platform.
func (c Config) Normalize() (Config, error) {
	if c.Version != 1 {
		return Config{}, errors.New("unsupported routing schema version")
	}
	if !validAction(c.Default) {
		return Config{}, errors.New("invalid default route")
	}
	out := Config{Version: 1, Default: c.Default}
	seen := map[string]Action{}
	for i, r := range c.Rules {
		if !validAction(r.Action) {
			return Config{}, fmt.Errorf("rule %d: invalid action", i+1)
		}
		var err error
		r.Value = strings.TrimSpace(r.Value)
		switch r.Kind {
		case Domain, Suffix:
			if strings.HasPrefix(r.Value, "*.") {
				r.Kind = Suffix
				r.Value = strings.TrimPrefix(r.Value, "*.")
			}
			r.Value, err = NormalizeDomain(r.Value)
		case CIDR:
			var p netip.Prefix
			p, err = netip.ParsePrefix(r.Value)
			if err != nil {
				if a, e := netip.ParseAddr(r.Value); e == nil {
					p = netip.PrefixFrom(a, a.BitLen())
					err = nil
				}
			}
			if err == nil {
				r.Value = p.Masked().String()
			}
		default:
			err = errors.New("unknown rule kind")
		}
		if err != nil {
			return Config{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
		if !r.Disabled {
			key := string(r.Kind) + ":" + r.Value
			if a, ok := seen[key]; ok {
				if a != r.Action {
					return Config{}, fmt.Errorf("rule %d: conflicting duplicate", i+1)
				}
				continue
			}
			seen[key] = r.Action
		}
		out.Rules = append(out.Rules, r)
	}
	// Exact > suffix (longest) > CIDR (longest prefix) > default.
	sort.SliceStable(out.Rules, func(i, j int) bool {
		a, b := out.Rules[i], out.Rules[j]
		rank := map[Kind]int{Domain: 0, Suffix: 1, CIDR: 2}
		if a.Kind != b.Kind {
			return rank[a.Kind] < rank[b.Kind]
		}
		if a.Kind == Suffix {
			return strings.Count(a.Value, ".") > strings.Count(b.Value, ".")
		}
		if a.Kind == CIDR {
			p, _ := netip.ParsePrefix(a.Value)
			q, _ := netip.ParsePrefix(b.Value)
			return p.Bits() > q.Bits()
		}
		return false
	})
	return out, nil
}

// Match consumes normalized rules. Domain identity takes precedence over the
// real destination IP; callers must not infer it from a reverse IP cache.
func (c Config) Match(domain string, ip netip.Addr) Action {
	domain, _ = NormalizeDomain(domain)
	for _, r := range c.Rules {
		if r.Disabled {
			continue
		}
		switch r.Kind {
		case Domain:
			if domain != "" && domain == r.Value {
				return r.Action
			}
		case Suffix:
			if domain != "" && (domain == r.Value || strings.HasSuffix(domain, "."+r.Value)) {
				return r.Action
			}
		case CIDR:
			p, _ := netip.ParsePrefix(r.Value)
			if p.Contains(ip) {
				return r.Action
			}
		}
	}
	return c.Default
}

// Compile emits only sing-box route rules. Platform hosts supply protected
// outbounds, DNS and a single TUN owner; this cannot install OS routes.
func (c Config) Compile() (json.RawMessage, error) {
	n, err := c.Normalize()
	if err != nil {
		return nil, err
	}
	compiled := []map[string]any{}
	for _, r := range n.Rules {
		if r.Disabled {
			continue
		}
		key := map[Kind]string{Domain: "domain", Suffix: "domain_suffix", CIDR: "ip_cidr"}[r.Kind]
		compiled = append(compiled, map[string]any{key: []string{r.Value}, "action": "route", "outbound": r.Action})
	}
	return json.Marshal(map[string]any{"rules": compiled, "final": n.Default})
}
