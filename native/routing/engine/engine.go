// Package engine owns the shared sing-box registry. Platform hosts retain
// responsibility for their existing VPN service, routes, DNS and protection.
package engine

import (
	"context"
	"errors"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func Context(ctx context.Context, host Underlay) context.Context {
	ctx = service.ContextWithDefaultRegistry(ctx)
	in := inbound.NewRegistry()
	tun.RegisterInbound(in)
	direct.RegisterInbound(in)
	mixed.RegisterInbound(in)
	out := outbound.NewRegistry()
	registerDirect(out, host)
	awg.Register(out, host.ListenPacket)
	d := dns.NewTransportRegistry()
	transport.RegisterUDP(d)
	transport.RegisterTCP(d)
	transport.RegisterTLS(d)
	transport.RegisterHTTPS(d)
	fakeip.RegisterTransport(d)
	hosts.RegisterTransport(d)
	return box.Context(ctx, in, out, endpoint.NewRegistry(), d, boxservice.NewRegistry(), certificate.NewRegistry())
}

// New parses context-aware options, including the AWG extension. Logs are
// disabled unless a future host explicitly installs redacted diagnostics.
// The host must install sing-box's PlatformInterface in ctx for mobile TUNs.
func New(ctx context.Context, raw []byte) (*box.Box, error) {
	var options option.Options
	if e := json.UnmarshalContext(ctx, raw, &options); e != nil {
		return nil, errors.New("invalid routing engine configuration")
	}
	options.Log = &option.LogOptions{Disabled: true}
	return box.New(box.Options{Context: ctx, Options: options})
}
