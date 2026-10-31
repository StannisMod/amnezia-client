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
