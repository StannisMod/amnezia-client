package engine

import (
	"context"
	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
)

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
