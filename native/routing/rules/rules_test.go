package rules

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func TestDomainIdentityAndPrecedence(t *testing.T) {
	c, e := (Config{Version: 1, Default: VPN, Rules: []Rule{
		{Kind: CIDR, Value: "192.168.1.1/16", Action: Direct},
		{Kind: Suffix, Value: "*.RU.", Action: Direct},
		{Kind: Domain, Value: "private.ru", Action: VPN},
		{Kind: Suffix, Value: "sub.ru", Action: VPN},
		{Kind: Domain, Value: "ПРИМЕР.РФ.", Action: Direct},
	}}).Normalize()
	if e != nil {
		t.Fatal(e)
	}
	ip := netip.MustParseAddr("192.168.5.6")
	for _, v := range []struct {
		name string
		ip   netip.Addr
		want Action
	}{
		{"a.ru", ip, Direct}, {"private.ru", ip, VPN}, {"SUB.RU.", ip, VPN},
		{"a.sub.ru", ip, VPN}, {"ru", netip.Addr{}, Direct},
		{"example.ru.attacker.test", netip.Addr{}, VPN}, {"notru", netip.Addr{}, VPN},
		{"xn--e1afmkfd.xn--p1ai", netip.Addr{}, Direct}, {"пример.рф", netip.Addr{}, Direct},
		{"", ip, Direct}, {"", netip.MustParseAddr("1.1.1.1"), VPN},
	} {
		if a := c.Match(v.name, v.ip); a != v.want {
			t.Errorf("%s: got %s want %s", v.name, a, v.want)
		}
	}
	if c.Match("a.ru", ip) == c.Match("private.ru", ip) {
		t.Fatal("shared IP lost domain identity")
	}
	b, e := c.Compile()
	if e != nil {
		t.Fatal(e)
	}
	var obj map[string]any
	if e = json.Unmarshal(b, &obj); e != nil {
		t.Fatal(e)
	}
	if obj["final"] != "vpn" {
		t.Fatal(string(b))
	}
}

func TestInvalidAndConflictingRules(t *testing.T) {
	for _, v := range []string{"*ru", "foo.*.ru", "https://foo.ru", "a..ru", "-a.ru", "a-.ru", "127.0.0.1", "*."} {
		_, e := (Config{Version: 1, Default: VPN, Rules: []Rule{{Kind: Domain, Value: v, Action: Direct}}}).Normalize()
		if e == nil {
			t.Errorf("accepted %q", v)
		}
	}
	_, e := (Config{Version: 1, Default: VPN, Rules: []Rule{{Domain, "FOO.ru", Direct, false}, {Domain, "foo.ru.", VPN, false}}}).Normalize()
	if e == nil {
		t.Fatal("accepted conflicting normalized duplicate")
	}
}

func TestInverseDisabledAndLongestPrefix(t *testing.T) {
	c, e := (Config{Version: 1, Default: Direct, Rules: []Rule{
		{CIDR, "10.0.0.0/8", Direct, false}, {CIDR, "10.1.0.0/16", VPN, false},
		{Domain, "vpn.test", VPN, false}, {Domain, "off.test", VPN, true},
	}}).Normalize()
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct {
		domain, ip string
		want       Action
	}{{"vpn.test", "1.2.3.4", VPN}, {"off.test", "1.2.3.4", Direct}, {"", "10.1.2.3", VPN}, {"", "10.2.3.4", Direct}} {
		if c.Match(v.domain, netip.MustParseAddr(v.ip)) != v.want {
			t.Fatal(v)
		}
	}
	data, _ := json.Marshal(c)
	var restored Config
	if e = json.Unmarshal(data, &restored); e != nil {
		t.Fatal(e)
	}
	if restored.Match("vpn.test", netip.Addr{}) != VPN {
		t.Fatal("roundtrip changed action")
	}
}
