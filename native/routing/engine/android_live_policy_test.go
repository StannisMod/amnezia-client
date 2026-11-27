package engine

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	J "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

func TestLiveAndroidOverridesPreserveBlocksAfterEverySwitch(t *testing.T) {
	config := RoutingConfig{Rules: rules.Config{Version: 2, Default: rules.Direct, Rules: []rules.Rule{
		{Kind: rules.Domain, Value: "blocked.test", Action: rules.Block},
		{Kind: rules.Domain, Value: "direct.test", Action: rules.Direct},
	}}, Resolver: netip.MustParseAddrPort("10.77.0.2:53"), ResolverAction: rules.VPN,
		AndroidApplications: &AndroidApplications{Live: true, SiteRulesUIDs: []uint32{10282}}}
	raw, err := config.compile(map[string]any{"type": "direct", "tag": "vpn"})
	if err != nil {
		t.Fatal(err)
	}
	stripped, live, err := splitLiveAndroidPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	var options struct {
		Route option.RouteOptions `json:"route"`
	}
	if err := J.UnmarshalContext(context.Background(), stripped, &options); err != nil {
		t.Fatal(err)
	}
	var parsed []adapter.Rule
	for _, entry := range options.Route.Rules {
		rule, err := R.NewRule(context.Background(), log.NewNOPFactory().NewLogger("test"), entry, true)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, rule)
	}
	if err := installLiveAndroidRules(parsed, live); err != nil {
		t.Fatal(err)
	}
	policy := findLiveAndroidPolicy(parsed)
	for _, uids := range [][]uint32{{10282}, {10281}, nil, {10281, 10282}} {
		snapshot, err := newAndroidUIDSnapshot(AndroidApplications{Live: true, SiteRulesUIDs: uids})
		if err != nil {
			t.Fatal(err)
		}
		policy.current.Store(snapshot)
		for _, uid := range []int32{-1, 10281, 10282} {
			for _, domain := range []string{"blocked.test", "direct.test", "ordinary.test"} {
				metadata := &adapter.InboundContext{Inbound: TUNTag, Domain: domain, Destination: M.ParseSocksaddrHostPort("198.51.100.2", 443)}
				if uid >= 0 {
					metadata.ProcessInfo = &adapter.ConnectionOwner{UserId: uid}
				}
				got := options.Route.Final
				for _, rule := range parsed {
					metadata.ResetRuleCache()
					if !rule.Match(metadata) {
						continue
					}
					switch action := rule.Action().(type) {
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
				for _, allowed := range uids {
					if int32(allowed) == uid {
						want = "direct"
					}
				}
				if domain == "blocked.test" {
					want = "reject"
				}
				if got != want {
					t.Fatalf("UID%d %s got%s want%s", uid, domain, got, want)
				}
			}
		}
	}
	var changed map[string]any
	json.Unmarshal(raw, &changed)
	changed["route"].(map[string]any)["final"] = "vpn"
	other, _ := json.Marshal(changed)
	first, _, _ := liveAndroidInvariant(raw)
	second, _, _ := liveAndroidInvariant(other)
	if first == second {
		t.Fatal("destination policy change escaped invariant")
	}
}
