package engine

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

func TestSessionCompilerUsesPinnedSingBoxSchema(t *testing.T) {
	priv, pub := keys(t)
	c := SessionConfig{
		Rules:    rules.Config{Version: 1, Default: rules.VPN, Rules: []rules.Rule{{Kind: rules.Suffix, Value: "*.ru", Action: rules.Direct}}},
		AWG:      awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: priv, PublicKey: pub, Endpoint: netip.MustParseAddrPort("127.0.0.1:12345"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		Resolver: netip.MustParseAddrPort("1.1.1.1:53"), ResolverAction: rules.VPN,
	}
	raw, e := c.Compile()
	if e != nil {
		t.Fatal(e)
	}
	var dial net.Dialer
	var lc net.ListenConfig
	ctx := Context(context.Background(), Underlay{DialContext: dial.DialContext, ListenPacket: lc.ListenPacket})
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
	instance, e := New(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	instance.Close()
	c.Resolver = netip.MustParseAddrPort("127.0.0.53:53")
	if _, e = c.Compile(); e == nil {
		t.Fatal("accepted VPN path for local DNS stub")
	}
	c.ResolverAction = rules.Direct
	if _, e = c.Compile(); e != nil {
		t.Fatal(e)
	}
}

func TestTransportEnvelopeAndCapabilities(t *testing.T) {
	private, public := keys(t)
	legacy := SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN}, Resolver: netip.MustParseAddrPort("1.1.1.1:53"), ResolverAction: rules.VPN,
		AWG: awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: private, PublicKey: public, Endpoint: netip.MustParseAddrPort("127.0.0.1:12345"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}}
	expected, err := legacy.Compile()
	if err != nil {
		t.Fatal(err)
	}
	explicit := legacy
	config := legacy.AWG
	explicit.AWG = awg.Config{}
	explicit.VPN = &TransportConfig{Type: "awg", AWG: &config}
	actual, err := explicit.Compile()
	if err != nil || string(actual) != string(expected) {
		t.Fatal("legacy AWG policy changed", err)
	}
	capabilities, err := explicit.VPN.Capabilities()
	if err != nil || !capabilities.TCP || !capabilities.UDP {
		t.Fatal("missing transport capabilities", err)
	}
	explicit.AWG = config
	if _, err = explicit.Compile(); err == nil {
		t.Fatal("accepted mixed legacy and explicit transports")
	}
	for _, transport := range []TransportConfig{{Type: "openvpn"}, {Type: "awg"}, {Type: "wireguard", AWG: &config}} {
		explicit.AWG = awg.Config{}
		explicit.VPN = &transport
		if _, err = explicit.Compile(); err == nil {
			t.Fatal("accepted unsupported or mismatched adapter", transport.Type)
		}
	}
	config.PrivateKey = "invalid"
	if _, err = (&TransportConfig{Type: "awg", AWG: &config}).Capabilities(); err == nil {
		t.Fatal("invalid credentials passed preflight")
	}
}
