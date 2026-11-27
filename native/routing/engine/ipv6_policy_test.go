package engine

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestDisabledIPv6RejectsCaptureAndAAAAWithoutNativeFallback(t *testing.T) {
	private, public := keys(t)
	enabled := false
	session := SessionConfig{
		IPv6Enabled: &enabled,
		Rules:       rules.Config{Version: 1, Default: rules.Direct},
		AWG: awg.Config{
			Address:    []netip.Addr{netip.MustParseAddr("10.77.0.1")},
			PrivateKey: private, PublicKey: public,
			Endpoint:   netip.MustParseAddrPort("127.0.0.1:9"),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		},
		Resolver: netip.MustParseAddrPort("127.0.0.1:9"), ResolverAction: rules.Direct,
	}
	raw, err := session.Compile()
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err = json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	// Drive the real router without creating/changing a host TUN.
	delete(config, "inbounds")
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var nativeDials atomic.Int32
	var dial net.Dialer
	var listen net.ListenConfig
	ctx = Context(ctx, Underlay{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			nativeDials.Add(1)
			return dial.DialContext(ctx, network, address)
		},
		ListenPacket: listen.ListenPacket,
	})
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
	instance, err := New(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	router := service.FromContext[adapter.DNSRouter](ctx)
	query := new(dns.Msg)
	query.SetQuestion("ipv6-disabled.test.", dns.TypeAAAA)
	answer, err := router.Exchange(adapter.WithContext(ctx, &adapter.InboundContext{Inbound: TUNTag}),
		query, adapter.DNSQueryOptions{})
	if err != nil || answer == nil || answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 {
		t.Fatal("disabled IPv6 must answer AAAA with NODATA", answer, err)
	}
	query.SetQuestion("ipv6-disabled.test.", dns.TypeA)
	answer, err = router.Exchange(adapter.WithContext(ctx, &adapter.InboundContext{Inbound: TUNTag}),
		query, adapter.DNSQueryOptions{})
	if err != nil || answer == nil || len(answer.Answer) != 1 || answer.Answer[0].Header().Rrtype != dns.TypeA {
		t.Fatal("disabling IPv6 broke IPv4 FakeIP DNS", answer, err)
	}
	client, capture := net.Pipe()
	defer client.Close()
	go instance.Router().RouteConnectionEx(ctx, capture, adapter.InboundContext{
		Inbound: TUNTag, Network: "tcp", Destination: M.ParseSocksaddr("[fd99::4]:18080"),
	}, nil)
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = client.Read(make([]byte, 1)); err == nil {
		t.Fatal("disabled IPv6 accepted data")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("IPv6 reject stalled")
	}
	if nativeDials.Load() != 0 {
		t.Fatal("disabled IPv6 escaped into native DNS or a DIRECT connection")
	}
}
