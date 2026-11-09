package engine

import (
	"encoding/json"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"net/netip"
	"testing"
)

// Application-only VPN does not need to inspect application protocols to
// choose an exit. Domain policies retain their established Host/SNI behavior.
func TestOrdinaryPolicyDoesNotInspectApplicationProtocols(t *testing.T) {
	for _, row := range []struct {
		name    string
		entries []rules.Rule
		inspect bool
	}{
		{"all-vpn", nil, false},
		{"ip-prefix", []rules.Rule{{Kind: rules.CIDR, Value: "192.0.2.0/24", Action: rules.Block}}, false},
		{"domain", []rules.Rule{{Kind: rules.Domain, Value: "direct.test", Action: rules.Direct}}, true},
		{"disabled-domain", []rules.Rule{{Kind: rules.Domain, Value: "direct.test", Action: rules.Direct, Disabled: true}}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			raw, err := (RoutingConfig{Rules: rules.Config{Version: 2, Default: rules.VPN, Rules: row.entries}, Resolver: netip.MustParseAddrPort("192.0.2.53:53"), ResolverAction: rules.VPN}).compile(map[string]any{"type": "direct", "tag": "vpn"})
			if err != nil {
				t.Fatal(err)
			}
			var compiled map[string]any
			if err = json.Unmarshal(raw, &compiled); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, item := range compiled["route"].(map[string]any)["rules"].([]any) {
				if item.(map[string]any)["action"] == "sniff" {
					found = true
				}
			}
			if found != row.inspect {
				t.Fatalf("unexpected protocol inspection: %v", found)
			}
		})
	}
}
