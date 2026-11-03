//go:build windows

package desktop

import (
	"strings"
	"testing"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
)

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
