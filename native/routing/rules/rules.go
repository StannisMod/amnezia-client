// Package rules defines the platform-neutral routing configuration. It never
// resolves hostnames into persistent IP rules.
package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

type Action string

const (
	Direct Action = "direct"
	VPN    Action = "vpn"
	Block  Action = "block"
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
	Network  string `json:"network,omitempty"`
	Ports    string `json:"ports,omitempty"`
}
type Config struct {
	Version int    `json:"version"`
	Default Action `json:"default"`
	Rules   []Rule `json:"rules"`
}

func validAction(a Action) bool { return a == Direct || a == VPN || a == Block }

// Reject fields this client cannot preserve instead of silently changing a
// portable policy. This also applies when a config arrives inside a session.
func (c *Config) UnmarshalJSON(data []byte) error {
	type plain Config
	var out plain
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&out); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	keys := []string{"version", "default"}
	// Old native sessions used a nil slice for an empty v1 rules list.
	if out.Version != 1 {
		keys = append(keys, "rules")
	}
	for _, key := range keys {
		if len(fields[key]) == 0 || string(fields[key]) == "null" {
			return fmt.Errorf("missing routing field %s", key)
		}
	}
	*c = Config(out)
	return nil
}

func (r *Rule) UnmarshalJSON(data []byte) error {
	type plain Rule
	var out plain
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&out); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for key, value := range fields {
		if string(value) == "null" {
			return fmt.Errorf("null rule field %s", key)
		}
	}
	*r = Rule(out)
	return nil
}

type portRange struct{ first, last int }

func parsePorts(s string) ([]portRange, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	if len(s) > 1024 {
		return nil, errors.New("too many port conditions")
	}
	var ranges []portRange
	for _, part := range strings.Split(s, ",") {
		ends := strings.Split(strings.TrimSpace(part), "-")
		if len(ends) > 2 {
			return nil, errors.New("invalid port range")
		}
		values := make([]int, len(ends))
		for i, end := range ends {
			end = strings.TrimSpace(end)
			if end == "" || strings.IndexFunc(end, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return nil, errors.New("invalid port")
			}
			n, err := strconv.Atoi(end)
			if err != nil || n < 1 || n > 65535 {
				return nil, errors.New("port outside 1-65535")
			}
			values[i] = n
		}
		last := values[len(values)-1]
		if values[0] > last {
			return nil, errors.New("reversed port range")
		}
		ranges = append(ranges, portRange{values[0], last})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].first < ranges[j].first })
	merged := ranges[:0]
	for _, p := range ranges {
		if len(merged) > 0 && p.first <= merged[len(merged)-1].last+1 {
			if p.last > merged[len(merged)-1].last {
				merged[len(merged)-1].last = p.last
			}
		} else {
			merged = append(merged, p)
		}
	}
	return merged, nil
}

func NormalizePorts(s string) (string, error) {
	ranges, err := parsePorts(s)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(ranges))
	for _, p := range ranges {
		part := strconv.Itoa(p.first)
		if p.first != p.last {
			part += "-" + strconv.Itoa(p.last)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ","), nil
}

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
	if c.Version != 1 && c.Version != 2 {
		return Config{}, errors.New("unsupported routing schema version")
	}
	if !validAction(c.Default) {
		return Config{}, errors.New("invalid default route")
	}
	if c.Version == 1 && c.Default == Block {
		return Config{}, errors.New("Block requires schema version 2")
	}
	if len(c.Rules) > 4096 {
		return Config{}, errors.New("too many routing rules")
	}
	out := Config{Version: c.Version, Default: c.Default, Rules: []Rule{}}
	seen := map[string]Action{}
	for i, r := range c.Rules {
		if c.Version == 1 && (r.Action == Block || r.Network != "" || r.Ports != "") {
			return Config{}, fmt.Errorf("rule %d: conditions and Block require schema version 2", i+1)
		}
		if !validAction(r.Action) {
			return Config{}, fmt.Errorf("rule %d: invalid action", i+1)
		}
		var err error
		if r.Network != "" && r.Network != "tcp" && r.Network != "udp" {
			return Config{}, fmt.Errorf("rule %d: invalid network", i+1)
		}
		r.Ports, err = NormalizePorts(r.Ports)
		if err != nil {
			return Config{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
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
			key := string(r.Kind) + ":" + r.Value + ":" + r.Network + ":" + r.Ports
			if _, ok := seen[key]; ok {
				return Config{}, fmt.Errorf("rule %d: duplicate conditions", i+1)
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
	return c.MatchFlow(domain, ip, "", 0)
}

// MatchFlow consumes normalized rules, with the same AND conditions emitted
// to sing-box. A missing port/network never satisfies a constrained rule.
func (c Config) MatchFlow(domain string, ip netip.Addr, network string, port uint16) Action {
	domain, _ = NormalizeDomain(domain)
	for _, r := range c.Rules {
		if r.Disabled {
			continue
		}
		if r.Network != "" && r.Network != network {
			continue
		}
		if r.Ports != "" {
			ranges, _ := parsePorts(r.Ports)
			matches := false
			for _, p := range ranges {
				if int(port) >= p.first && int(port) <= p.last {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
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
		item := map[string]any{key: []string{r.Value}, "action": "route", "outbound": r.Action}
		if r.Network != "" {
			item["network"] = []string{r.Network}
		}
		if r.Ports != "" {
			ranges, _ := parsePorts(r.Ports)
			// sing-box ORs port and port_range within the port condition.
			var singles []int
			var spans []string
			for _, p := range ranges {
				if p.first == p.last {
					singles = append(singles, p.first)
				} else {
					spans = append(spans, fmt.Sprintf("%d:%d", p.first, p.last))
				}
			}
			if len(singles) > 0 {
				item["port"] = singles
			}
			if len(spans) > 0 {
				item["port_range"] = spans
			}
		}
		if r.Action == Block {
			delete(item, "outbound")
			item["action"] = "reject"
			item["method"] = "drop"
		}
		compiled = append(compiled, item)
	}
	final := n.Default
	if final == Block {
		compiled = append(compiled, map[string]any{"action": "reject", "method": "drop"})
		final = Direct // Unreachable fallback: every remaining flow is rejected.
	}
	return json.Marshal(map[string]any{"rules": compiled, "final": final})
}
