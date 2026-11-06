//go:build windows

package desktop

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
)

func TestWindowsDoHUpgradePreservesEndpointAndRejectsDowngrade(t *testing.T) {
	snapshot := dnspolicy.NetworkSnapshot{Links: []dnspolicy.NetworkLink{{ID: "native", Default: true, Servers: []dnspolicy.NetworkServer{{Address: netip.MustParseAddr("192.0.2.53")}}}}}
	if err := applyWindowsEncryptedDNS(&snapshot, []byte(`{"ServerAddress":"192.0.2.53","DohTemplate":"https://dns.example:8443/dns-query{?dns}"}`)); err != nil {
		t.Fatal(err)
	}
	server := snapshot.Links[0].Servers[0]
	if server.Transport != "https" || server.ServerName != "dns.example" || server.Port != 8443 || server.HTTPSPath != "/dns-query" {
		t.Fatal("DoH endpoint/authentication metadata was changed")
	}
	if err := applyWindowsEncryptedDNS(&snapshot, []byte(`{"ServerAddress":"192.0.2.53","DohTemplate":"http://dns.example/dns-query"}`)); err == nil {
		t.Fatal("plaintext downgrade accepted")
	}
}

func TestWindowsNetworkDNSInventoryAndSystemPolicies(t *testing.T) {
	snapshot, err := windowsNetworkDNS()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Links) == 0 {
		t.Skip("no native DNS adapters on this host")
	}
	for _, link := range snapshot.Links {
		if link.ID == "" || !strings.HasPrefix(link.Interface, "win:") || strings.EqualFold(link.Name, InterfaceName) {
			t.Fatal("invalid or captured DNS interface")
		}
		for _, server := range link.Servers {
			if err := dnspolicy.CheckAddress(server.Address, rules.Direct); err != nil {
				t.Fatal(err)
			}
		}
	}
	before, err := windowsDNSPolicyVersion()
	if err != nil {
		t.Fatal(err)
	}
	if err = addWindowsNRPT(&snapshot); err != nil {
		t.Fatal(err)
	}
	if !snapshot.RoutingDomainsAvailable {
		t.Fatal("NRPT inventory not completed")
	}
	if err = addWindowsEncryptedDNS(&snapshot); err != nil {
		t.Fatal(err)
	}
	after, err := windowsDNSPolicyVersion()
	if err != nil || before != after {
		t.Fatal("read-only DNS discovery changed system policy", err)
	}
}
