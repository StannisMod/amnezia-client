//go:build linux && !android

package desktop

import (
	"net/netip"
	"testing"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
)

func TestCorporateDNSPoliciesKeepInterfaceAndExplicitPriority(t *testing.T) {
	c := dnspolicy.Config{Version: 1, Default: "vpn", PreserveNetworkDomains: true, Policies: map[string]dnspolicy.Resolver{"vpn": {Transport: "udp", Server: "1.1.1.1", Path: rules.VPN}}, Rules: []dnspolicy.Rule{{Kind: rules.Domain, Value: "public.corp.example", Policy: "vpn"}}}
	links := []networkDNSLink{{Index: 7, Name: "corp0", Servers: []netip.Addr{netip.MustParseAddr("192.168.42.53")}, Domains: []string{"corp.example", "research.example"}}}
	if err := addNetworkDNS(&c, links); err != nil {
		t.Fatal(err)
	}
	if c.PreserveNetworkDomains || c.Policies["network-7"].Interface != "corp0" || c.Policies["network-7"].Path != rules.Direct {
		t.Fatal("lost native corporate policy", c)
	}
	compiled, err := c.Compile(rules.Config{Version: 1, Default: rules.VPN}, "tun")
	if err != nil {
		t.Fatal(err)
	}
	entries := compiled["rules"].([]any)
	if entries[1].(map[string]any)["server"] != dnspolicy.Tag("vpn") || entries[2].(map[string]any)["server"] != dnspolicy.Tag("network-7") {
		t.Fatal("system DNS overrode explicit exception")
	}
	for _, s := range compiled["servers"].([]any) {
		server := s.(map[string]any)
		if server["tag"] == dnspolicy.Tag("network-7") && server["detour"] != "dns-direct-network-7" {
			t.Fatal("corporate DNS lost scoped DIRECT path")
		}
	}
	changed := append([]networkDNSLink(nil), links...)
	changed[0].Name = "other0"
	if networkDNSFingerprint(links) == networkDNSFingerprint(changed) {
		t.Fatal("network scope change was not detected")
	}
}

func TestCorporateDNSAmbiguousLinksAreRejected(t *testing.T) {
	c := dnspolicy.Config{Policies: map[string]dnspolicy.Resolver{}}
	links := []networkDNSLink{
		{Index: 1, Name: "corp0", Servers: []netip.Addr{netip.MustParseAddr("192.168.1.53")}, Domains: []string{"corp.example"}},
		{Index: 2, Name: "corp1", Servers: []netip.Addr{netip.MustParseAddr("192.168.2.53")}, Domains: []string{"corp.example"}},
	}
	if err := addNetworkDNS(&c, links); err == nil {
		t.Fatal("ambiguous corporate domains could leak across interfaces")
	}
}

func TestNetworkDNSSourceRequiresUnambiguousNativeInterface(t *testing.T) {
	c := dnspolicy.Config{Policies: map[string]dnspolicy.Resolver{"local": {Source: "network", Transport: "udp", Path: rules.Direct}}}
	links := []networkDNSLink{{Index: 7, Name: "eth0", DefaultRoute: true, Servers: []netip.Addr{netip.MustParseAddr("192.168.42.53")}}}
	if err := bindNetworkDNS(&c, links); err != nil {
		t.Fatal(err)
	}
	if c.Policies["local"].Source != "" || c.Policies["local"].Interface != "eth0" || c.Policies["local"].Server != "192.168.42.53" {
		t.Fatal("network DNS was not pinned to its native scope")
	}
	c.Policies["local"] = dnspolicy.Resolver{Source: "network", Transport: "udp", Path: rules.Direct}
	links = append(links, networkDNSLink{Index: 8, Name: "wlan0", DefaultRoute: true, Servers: []netip.Addr{netip.MustParseAddr("192.168.0.1")}})
	if err := bindNetworkDNS(&c, links); err == nil {
		t.Fatal("ambiguous uplinks were silently merged")
	}
}
