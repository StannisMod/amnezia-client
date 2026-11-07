//go:build (linux && !android) || windows

package main

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRecoveryCommandCannotReplacePeerConfiguration(t *testing.T) {
	for _, input := range []string{
		`{"type":"refresh_underlay","request_id":1,"address":"192.0.2.8"}`,
		`{"type":"refresh_underlay","request_id":2,"address":"2001:db8::8"}`,
		`{"type":"refresh_underlay","request_id":3}`,
	} {
		r, endpoint, err := parseRecoveryRequest(input, 51820)
		if err != nil || r.ID == 0 {
			t.Fatal(err)
		}
		if r.Address != "" && (endpoint.Port() != 51820 || endpoint.Addr() != netip.MustParseAddr(r.Address)) {
			t.Fatal("changed configured port/address")
		}
	}
	for _, input := range []string{
		`{"type":"activate","request_id":1}`,
		`{"type":"refresh_underlay","request_id":0}`,
		`{"type":"refresh_underlay","request_id":-1}`,
		`{"type":"refresh_underlay","request_id":1.5}`,
		`{"type":"refresh_underlay","request_id":9007199254740992}`,
		`{"type":"refresh_underlay","request_id":1,"address":"vpn.test"}`,
		`{"type":"refresh_underlay","request_id":1,"address":"192.0.2.8:9999"}`,
		`{"type":"refresh_underlay","request_id":1,"address":"::"}`,
		`{"type":"refresh_underlay","request_id":1,"address":"ff02::1"}`,
		`{"type":"refresh_underlay","request_id":1,"address":"fe80::1%eth0"}`,
		`{"type":"refresh_underlay","request_id":1,"public_key":"other"}`,
		`{"type":"refresh_underlay","request_id":1,"port":9999}`,
		`{"type":"refresh_underlay","request_id":1} {}`,
		strings.Repeat("x", 2049),
	} {
		if _, _, err := parseRecoveryRequest(input, 51820); err == nil {
			t.Fatal("accepted unsafe command", input)
		}
	}
}
