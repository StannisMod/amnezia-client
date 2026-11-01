package engine

import (
	"context"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

// Evaluate the actual pinned sing-box rule parser/matcher, including reject
// semantics and ordering. Native tests independently verify kernel ownership.
func TestApplicationScopeAndDomainPrecedence(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		c := SessionConfig{Resolver: netip.MustParseAddrPort("1.1.1.1:53"), ResolverAction: rules.VPN,
			Rules:        rules.Config{Version: 1, Default: rules.VPN, Rules: []rules.Rule{{Kind: rules.Domain, Value: "direct.test", Action: rules.Direct}}},
			Applications: &ApplicationScope{Mode: mode, Paths: []string{"/opt/selected.app"}}}
		raw, err := c.Compile()
		if err != nil {
			t.Fatal(err)
		}
		var options struct {
			Route option.RouteOptions `json:"route"`
		}
		if err = json.UnmarshalContext(context.Background(), raw, &options); err != nil {
			t.Fatal(err)
		}
		var parsed []adapter.Rule
		for _, o := range options.Route.Rules {
			r, err := R.NewRule(context.Background(), log.NewNOPFactory().NewLogger("test"), o, true)
			if err != nil {
				t.Fatal(err)
			}
			parsed = append(parsed, r)
		}
		choose := func(path, domain string, port uint16) string {
			metadata := adapter.InboundContext{Inbound: TUNTag, Domain: domain, Destination: M.ParseSocksaddrHostPort("198.18.0.5", port)}
			if path != "" {
				metadata.ProcessInfo = &adapter.ConnectionOwner{ProcessPath: path}
			}
			for _, r := range parsed {
				metadata.ResetRuleCache()
				if r.Match(&metadata) {
					if route, ok := r.Action().(*R.RuleActionRoute); ok {
						return route.Outbound
					}
					return r.Action().Type()
				}
			}
			return string(c.Rules.Default)
		}
		for _, p := range []string{"/opt/selected.app", "/opt/selectedXapp", "/opt/other"} {
			want := "direct"
			inside := p == "/opt/selected.app"
			if mode == "exclude" {
				inside = !inside
			}
			if inside {
				want = "vpn"
			}
			if got := choose(p, "vpn.test", 443); got != want {
				t.Fatalf("%s %s: got %s want %s", mode, p, got, want)
			}
			if got := choose(p, "direct.test", 443); got != "direct" {
				t.Fatal("domain exception lost", mode, p, got)
			}
		}
		if choose("", "vpn.test", 443) != "reject" {
			t.Fatal("unidentified process escaped")
		}
		if choose("", "", 53) != "hijack-dns" {
			t.Fatal("shared system DNS lost FakeIP capture")
		}
		if runtime.GOOS == "windows" && choose(strings.ToUpper("/opt/selected.app"), "vpn.test", 443) != choose("/opt/selected.app", "vpn.test", 443) {
			t.Fatal("Windows process identity must ignore case")
		}
	}
}
