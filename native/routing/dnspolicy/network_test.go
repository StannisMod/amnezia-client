package dnspolicy

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/StannisMod/amnezia-client/native/routing/rules"
)

func TestNetworkSnapshotSelectsScopedDNSAndDoesNotInventDomainRules(t *testing.T) {
	c, route := fixture()
	c.Policies["lan"] = Resolver{Source: "network", Transport: "udp", Path: rules.Direct}
	snapshot := NetworkSnapshot{Links: []NetworkLink{{ID: "wifi", Interface: "native-wifi", Name: "Wi-Fi", Default: true, Servers: []NetworkServer{{Address: netip.MustParseAddr("192.168.20.53")}}, SearchDomains: []string{"corp.example"}}}}
	prepared, err := snapshot.Prepare(c)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Policies["lan"].Interface != "native-wifi" || prepared.Policies["lan"].Server != "192.168.20.53" {
		t.Fatal("lost network binding")
	}
	if len(prepared.NetworkRules) != 0 {
		t.Fatal("search suffix became a routing policy")
	}
	if c.Policies["lan"].Source != "network" {
		t.Fatal("prepared snapshot modified saved user settings")
	}
	if _, err = prepared.Compile(route, "tun"); err != nil {
		t.Fatal(err)
	}
	snapshot.Links[0].Servers[0].Address = netip.MustParseAddr("192.168.21.53")
	fresh, err := snapshot.Prepare(c)
	if err != nil || fresh.Policies["lan"].Server == prepared.Policies["lan"].Server {
		t.Fatal("reconnect reused old network DNS")
	}
	c.PreserveNetworkDomains = true
	if _, err = snapshot.Prepare(c); err == nil {
		t.Fatal("invented corporate domain discovery")
	}
}

func TestNetworkPrivateDNSPreservesEncryptionAndVerificationMode(t *testing.T) {
	for _, opportunistic := range []bool{false, true} {
		c, route := fixture()
		c.Policies["lan"] = Resolver{Source: "network", Transport: "udp", Path: rules.Direct}
		server := NetworkServer{Address: netip.MustParseAddr("9.9.9.9"), Transport: "tls", Port: 853, ServerName: "dns.example", OpportunisticTLS: opportunistic}
		if opportunistic {
			server.ServerName = ""
		}
		prepared, err := (NetworkSnapshot{Links: []NetworkLink{{ID: "wifi", Interface: "android-123", Default: true, Servers: []NetworkServer{server}}}}).Prepare(c)
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := prepared.Compile(route, "tun")
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range compiled["servers"].([]any) {
			s := item.(map[string]any)
			if s["tag"] != Tag("lan") {
				continue
			}
			if s["type"] != "tls" || s["server_port"] != uint16(853) || s["detour"] != "dns-direct-lan" {
				t.Fatal("private DNS downgraded or unbound", s)
			}
			tls := s["tls"].(map[string]any)
			if opportunistic {
				if tls["insecure"] != true {
					t.Fatal("opportunistic encryption semantics lost")
				}
			} else if tls["server_name"] != "dns.example" || tls["insecure"] != nil {
				t.Fatal("strict private DNS lost authentication")
			}
		}
	}
	var invalid Config
	if json.Unmarshal([]byte(`{"policies":{"lan":{"networkTLSOpportunistic":true}}}`), &invalid) == nil {
		t.Fatal("user policy could disable TLS verification through a native-only field")
	}
}

func TestNetworkSnapshotCorporateExactAndSuffixPriority(t *testing.T) {
	c, route := fixture()
	c.PreserveNetworkDomains = true
	snapshot := NetworkSnapshot{RoutingDomainsAvailable: true, Links: []NetworkLink{{ID: "nrpt", Servers: []NetworkServer{{Address: netip.MustParseAddr("192.168.30.53")}}, RoutingRules: []NetworkDomain{{Kind: rules.Suffix, Value: "internal.example"}, {Kind: rules.Domain, Value: "public.internal.example"}}}}}
	prepared, err := snapshot.Prepare(c)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := prepared.Compile(route, "tun")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(compiled)
	if strings.Index(string(encoded), "public.corp.example") > strings.Index(string(encoded), "public.internal.example") {
		t.Fatal("native corporate rule overrode explicit DNS exception")
	}
	if prepared.PreserveNetworkDomains || len(prepared.NetworkRules) != 2 {
		t.Fatal("corporate rules were not prepared")
	}
}
