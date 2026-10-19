// Package engine owns the shared sing-box registry. Platform hosts retain
// responsibility for their existing VPN service, routes, DNS and protection.
package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"

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
	return NewWithCache(ctx, raw, "")
}

// NewWithCache preserves domain/FakeIP identity across transport restarts and
// process death. Hosts choose an absolute path in their private app storage.
// Real DNS answers are deliberately not persisted across network changes.
func NewWithCache(ctx context.Context, raw []byte, cachePath string) (*box.Box, error) {
	var options option.Options
	if e := json.UnmarshalContext(ctx, raw, &options); e != nil {
		return nil, errors.New("invalid routing engine configuration")
	}
	options.Log = &option.LogOptions{Disabled: true}
	if cachePath != "" {
		if !filepath.IsAbs(cachePath) {
			return nil, errors.New("routing cache requires private absolute path")
		}
		file, err := os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, errors.New("routing cache unavailable")
		}
		err = file.Chmod(0o600)
		file.Close()
		if err != nil {
			return nil, errors.New("routing cache permissions unavailable")
		}
		if options.Experimental == nil {
			options.Experimental = &option.ExperimentalOptions{}
		}
		options.Experimental.CacheFile = &option.CacheFileOptions{Enabled: true, Path: cachePath, CacheID: "amnezia-domain-routing-v1", StoreFakeIP: true}
	}
	return box.New(box.Options{Context: ctx, Options: options})
}
