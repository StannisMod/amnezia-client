package nativedns

import (
	"context"
	"net/netip"
	"testing"
)

func TestSessionRejectsMalformedConfiguration(t *testing.T) {
	for _, raw := range []string{
		`{`, `{"bindings":[],"fallback":"8.8.8.8"}`,
		`{"bindings":[]} {}`, `{"bindings":[]} null`,
	} {
		if _, err := ParseConfig(raw); err == nil {
			t.Fatal("accepted malformed/unknown config", raw)
		}
	}
	endpoint := netip.MustParseAddrPort("127.0.0.1:53")
	upstream := netip.MustParseAddrPort("192.0.2.53:53")
	binding := Binding{Endpoint: endpoint, Upstream: upstream, InterfaceName: "lo", InterfaceIndex: 1}
	for _, config := range []Config{
		{}, {Bindings: []Binding{binding, binding}},
		{Bindings: []Binding{{Endpoint: endpoint, Upstream: endpoint}}},
		{Bindings: []Binding{{Endpoint: netip.MustParseAddrPort("127.0.0.1:5300"), Upstream: upstream}}},
	} {
		if session, err := Start(context.Background(), config); err == nil {
			session.Close()
			t.Fatal("accepted invalid session", config)
		}
	}
}
