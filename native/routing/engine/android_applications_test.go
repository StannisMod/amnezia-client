package engine

import (
	"context"
	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

func TestAndroidApplicationOverridePreservesBlocks(t *testing.T) {
	c := RoutingConfig{Rules: rules.Config{Version: 2, Default: rules.Direct, Rules: []rules.Rule{
		{Kind: rules.Domain, Value: "blocked.test", Action: rules.Block},
		{Kind: rules.Domain, Value: "direct.test", Action: rules.Direct},
		{Kind: rules.CIDR, Value: "192.0.2.0/24", Action: rules.Block},
	}}, Resolver: netip.MustParseAddrPort("10.77.0.2:53"), ResolverAction: rules.VPN, AndroidApplications: &AndroidApplications{SiteRulesUIDs: []uint32{10282}}}
	raw, err := c.compile(map[string]any{"type": "direct", "tag": "vpn"})
	if err != nil {
		t.Fatal(err)
	}
	var options struct {
		Route option.RouteOptions `json:"route"`
	}
	if err := json.UnmarshalContext(context.Background(), raw, &options); err != nil {
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
	for _, uid := range []int32{-1, 10281, 10282} {
		for _, domain := range []string{"blocked.test", "direct.test", "ordinary.test", "ip-block.test"} {
			address := "198.51.100.2"
			if domain == "ip-block.test" {
				address = "192.0.2.7"
			}
			metadata := &adapter.InboundContext{Inbound: TUNTag, Domain: domain, Destination: M.ParseSocksaddrHostPort(address, 443)}
			if uid >= 0 {
				metadata.ProcessInfo = &adapter.ConnectionOwner{UserId: uid}
			}
			got := options.Route.Final
			for _, r := range parsed {
				metadata.ResetRuleCache()
				if !r.Match(metadata) {
					continue
				}
				switch action := r.Action().(type) {
				case *R.RuleActionRoute:
					got = action.Outbound
				case *R.RuleActionReject:
					got = "reject"
				default:
					continue
				}
				break
			}
			want := "vpn"
			if uid == 10282 {
				want = "direct"
			}
			if domain == "blocked.test" || domain == "ip-block.test" {
				want = "reject"
			}
			if got != want {
				t.Fatalf("UID %d %s: got %s want %s", uid, domain, got, want)
			}
		}
	}
}

func TestAndroidApplicationDNSRejectsUnsafeResolver(t *testing.T) {
	apps := &AndroidApplications{SiteRulesUIDs: []uint32{10282}}
	settings := func() map[string]any { return map[string]any{"rules": []any{map[string]any{"server": "fake"}}} }
	if err := apps.applyDNS(settings(), nil, rules.Direct); err == nil {
		t.Fatal("accepted DIRECT resolver for always-VPN apps")
	}
	for _, config := range []*dnspolicy.Config{
		{VPN: "missing", Policies: map[string]dnspolicy.Resolver{}},
		{VPN: "lan", Policies: map[string]dnspolicy.Resolver{"lan": {Path: rules.Direct}}},
	} {
		if err := apps.applyDNS(settings(), config, rules.VPN); err == nil {
			t.Fatal("accepted missing or DIRECT VPN DNS policy")
		}
	}
}

func TestAndroidApplicationVPNPriority(t *testing.T) {
	for _, uids := range [][]uint32{nil, {10281, 10282}} {
		compiled, err := (&AndroidApplications{SiteRulesUIDs: uids}).compile()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(compiled[0])
		if err != nil {
			t.Fatal(err)
		}
		var options option.Rule
		if err := json.UnmarshalContext(context.Background(), raw, &options); err != nil {
			t.Fatal(err)
		}
		rule, err := R.NewRule(context.Background(), log.NewNOPFactory().NewLogger("test"), options, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, uid := range []int32{-1, 0, 10280, 10281, 10282, 110281} {
			metadata := &adapter.InboundContext{}
			if uid >= 0 {
				metadata.ProcessInfo = &adapter.ConnectionOwner{UserId: uid}
			}
			want := len(uids) == 0 || (uid != 10281 && uid != 10282)
			if got := rule.Match(metadata); got != want {
				t.Fatalf("UID %d: VPN override=%v want %v", uid, got, want)
			}
			if rule.Action().(*R.RuleActionRoute).Outbound != "vpn" {
				t.Fatal("override escaped VPN")
			}
		}
	}
}

func TestAndroidApplicationInvalidUIDs(t *testing.T) {
	for _, uids := range [][]uint32{{0}, {10281, 10281}, {2147483648}, make([]uint32, 4097)} {
		if _, err := (&AndroidApplications{SiteRulesUIDs: uids}).compile(); err == nil {
			t.Fatal("accepted invalid UID list")
		}
	}
}
