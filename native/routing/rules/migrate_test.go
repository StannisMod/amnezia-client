package rules

import (
	"net/netip"
	"testing"
)

func TestMigrateIgnoresCachedDNS(t *testing.T) {
	c, e := FromLegacy(true, 2, map[string][]string{"example.com": {"203.0.113.7"}, "192.168.0.0/16": {}, "*.ru": {}})
	if e != nil {
		t.Fatal(e)
	}
	if c.Match("example.com", netip.Addr{}) != Direct {
		t.Fatal("lost domain")
	}
	if c.Match("unrelated.test", netip.MustParseAddr("203.0.113.7")) != VPN {
		t.Fatal("cached IP escaped domain policy")
	}
	if c.Match("a.ru", netip.Addr{}) != Direct {
		t.Fatal("lost wildcard")
	}
	if c.Match("", netip.MustParseAddr("192.168.0.1")) != Direct {
		t.Fatal("lost CIDR")
	}
	c, e = FromLegacy(true, 1, map[string][]string{"example.com": {}})
	if e != nil {
		t.Fatal(e)
	}
	if c.Default != Direct || c.Match("example.com", netip.Addr{}) != VPN {
		t.Fatal("inverse migration changed mode")
	}
}
