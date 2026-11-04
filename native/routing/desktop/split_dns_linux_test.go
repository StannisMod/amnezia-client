//go:build linux && !android

package desktop

import (
	"net/netip"
	"testing"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/godbus/dbus/v5"
)

func TestNetworkDNSExDecodesPortAndAuthenticationName(t *testing.T) {
	// D-Bus decodes wire structs as slices of interface values.
	variant := dbus.MakeVariant([][]any{{int32(7), int32(2), []byte{192, 0, 2, 53}, uint16(8853), "dns.corp.example"}})
	var servers []networkDNSServer
	if err := variant.Store(&servers); err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].Port != 8853 || servers[0].ServerName != "dns.corp.example" {
		t.Fatal("lost DNSEx metadata", servers)
	}
}

func TestLinuxNetworkDNSEncryptionAndPolicyImports(t *testing.T) {
	for _, tc := range []struct {
		name, global, link, transport string
		opportunistic                 bool
	}{
		{"inherited strict", "yes", "", "tls", false},
		{"link strict", "no", "yes", "tls", false},
		{"link overrides global", "yes", "no", "udp", false},
		{"inherited opportunistic", "opportunistic", "", "tls", true},
		{"link opportunistic", "yes", "opportunistic", "tls", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, err := networkDNSTransport(dnspolicy.NetworkServer{
				Address: netip.MustParseAddr("192.0.2.53"), Port: 8853, ServerName: "dns.corp.example",
			}, tc.global, tc.link)
			if err != nil {
				t.Fatal(err)
			}
			if server.Transport != tc.transport || server.OpportunisticTLS != tc.opportunistic {
				t.Fatal(server)
			}
			c := dnspolicy.Config{Version: 1, Default: "local", PreserveNetworkDomains: true,
				Policies: map[string]dnspolicy.Resolver{"local": {Source: "network", Transport: "udp", Path: rules.Direct}}}
			links := []networkDNSLink{{Index: 7, Name: "eth0", DefaultRoute: true,
				Servers: []dnspolicy.NetworkServer{server}, Domains: []string{"corp.example"}}}
			if err := bindNetworkDNS(&c, links); err != nil {
				t.Fatal(err)
			}
			if err := addNetworkDNS(&c, links); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"local", "network-7"} {
				p := c.Policies[id]
				if p.Transport != tc.transport || p.Port != 8853 || p.Interface != "eth0" || p.ServerName != server.ServerName {
					t.Fatalf("%s lost native transport: %+v", id, p)
				}
			}
			compiled, err := c.Compile(rules.Config{Version: 1, Default: rules.VPN}, "tun")
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range compiled["servers"].([]any) {
				upstream := entry.(map[string]any)
				if upstream["tag"] != dnspolicy.Tag("local") && upstream["tag"] != dnspolicy.Tag("network-7") {
					continue
				}
				if upstream["type"] != tc.transport {
					t.Fatal("plaintext downgrade", upstream)
				}
				if tc.transport == "tls" {
					tls := upstream["tls"].(map[string]any)
					if (tls["insecure"] == true) != tc.opportunistic || tls["server_name"] != "dns.corp.example" {
						t.Fatal(tls)
					}
				}
			}
			changed := append([]networkDNSLink(nil), links...)
			changed[0].Servers = append([]dnspolicy.NetworkServer(nil), links[0].Servers...)
			changed[0].Servers[0].Port++
			if networkDNSFingerprint(changed) == networkDNSFingerprint(links) {
				t.Fatal("port change not detected")
			}
		})
	}
	if _, err := networkDNSTransport(dnspolicy.NetworkServer{}, "unknown", ""); err == nil {
		t.Fatal("unknown encryption mode silently downgraded")
	}
}

func TestCorporateDNSPoliciesKeepInterfaceAndExplicitPriority(t *testing.T) {
	c := dnspolicy.Config{Version: 1, Default: "vpn", PreserveNetworkDomains: true, Policies: map[string]dnspolicy.Resolver{"vpn": {Transport: "udp", Server: "1.1.1.1", Path: rules.VPN}}, Rules: []dnspolicy.Rule{{Kind: rules.Domain, Value: "public.corp.example", Policy: "vpn"}}}
	links := []networkDNSLink{{Index: 7, Name: "corp0", Servers: []dnspolicy.NetworkServer{{Address: netip.MustParseAddr("192.168.42.53")}}, Domains: []string{"corp.example", "research.example"}}}
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
		{Index: 1, Name: "corp0", Servers: []dnspolicy.NetworkServer{{Address: netip.MustParseAddr("192.168.1.53")}}, Domains: []string{"corp.example"}},
		{Index: 2, Name: "corp1", Servers: []dnspolicy.NetworkServer{{Address: netip.MustParseAddr("192.168.2.53")}}, Domains: []string{"corp.example"}},
	}
	if err := addNetworkDNS(&c, links); err == nil {
		t.Fatal("ambiguous corporate domains could leak across interfaces")
	}
}

func TestNetworkDNSSourceRequiresUnambiguousNativeInterface(t *testing.T) {
	c := dnspolicy.Config{Policies: map[string]dnspolicy.Resolver{"local": {Source: "network", Transport: "udp", Path: rules.Direct}}}
	links := []networkDNSLink{{Index: 7, Name: "eth0", DefaultRoute: true, Servers: []dnspolicy.NetworkServer{{Address: netip.MustParseAddr("192.168.42.53")}}}}
	if err := bindNetworkDNS(&c, links); err != nil {
		t.Fatal(err)
	}
	if c.Policies["local"].Source != "" || c.Policies["local"].Interface != "eth0" || c.Policies["local"].Server != "192.168.42.53" {
		t.Fatal("network DNS was not pinned to its native scope")
	}
	c.Policies["local"] = dnspolicy.Resolver{Source: "network", Transport: "udp", Path: rules.Direct}
	links = append(links, networkDNSLink{Index: 8, Name: "wlan0", DefaultRoute: true, Servers: []dnspolicy.NetworkServer{{Address: netip.MustParseAddr("192.168.0.1")}}})
	if err := bindNetworkDNS(&c, links); err == nil {
		t.Fatal("ambiguous uplinks were silently merged")
	}
}
