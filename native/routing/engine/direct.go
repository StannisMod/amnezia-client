package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// Underlay is supplied by the native host. Both callbacks must create sockets
// exempt from VPN capture while preserving native destination route lookup.
// Binding every destination to the default physical gateway is not valid.
type Underlay struct {
	DialContext  func(context.Context, string, string) (net.Conn, error)
	ListenPacket func(context.Context, string, string) (net.PacketConn, error)
	// OnInterface is optional and used only by explicitly scoped DNS policies.
	// Ordinary DIRECT must keep destination-specific native routing.
	OnInterface  func(string) (Underlay, error)
}

type directOptions struct {
	Interface string `json:"interface,omitempty"`
}
type nativeDirect struct {
	outbound.Adapter
	host Underlay
	dns  adapter.DNSRouter
}

func registerDirect(r *outbound.Registry, host Underlay) {
	outbound.Register[directOptions](r, "direct", func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options directOptions) (adapter.Outbound, error) {
		selected := host
		if options.Interface != "" {
			if host.OnInterface == nil {
				return nil, errors.New("native DNS interface binding is unavailable")
			}
			var err error
			selected, err = host.OnInterface(options.Interface)
			if err != nil {
				return nil, err
			}
		}
		if selected.DialContext == nil || selected.ListenPacket == nil {
			return nil, errors.New("DIRECT requires native protected sockets")
		}
		return &nativeDirect{Adapter: outbound.NewAdapter("direct", tag, []string{"tcp", "udp"}, nil), host: selected, dns: service.FromContext[adapter.DNSRouter](ctx)}, nil
	})
}
func (d *nativeDirect) addresses(ctx context.Context, dst M.Socksaddr) ([]netip.Addr, error) {
	if dst.IsIP() {
		return []netip.Addr{dst.Addr}, nil
	}
	return d.dns.Lookup(ctx, dst.Fqdn, adapter.DNSQueryOptions{})
}
func (d *nativeDirect) DialContext(ctx context.Context, n string, dst M.Socksaddr) (net.Conn, error) {
	addresses, e := d.addresses(ctx, dst)
	if e != nil {
		return nil, e
	}
	for _, a := range addresses {
		c, e := d.host.DialContext(ctx, n, netip.AddrPortFrom(a, dst.Port).String())
		if e == nil {
			return c, nil
		}
	}
	return nil, errors.New("DIRECT destination unavailable")
}
func (d *nativeDirect) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	addresses, e := d.addresses(ctx, dst)
	if e != nil {
		return nil, e
	}
	if len(addresses) == 0 {
		return nil, errors.New("DIRECT destination has no addresses")
	}
	a := addresses[0]
	n, local := "udp4", "0.0.0.0:0"
	if a.Is6() {
		n, local = "udp6", "[::]:0"
	}
	pc, e := d.host.ListenPacket(ctx, n, local)
	if e != nil {
		return nil, e
	}
	if dst.IsDomain() {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(pc), M.SocksaddrFrom(a, dst.Port), dst), nil
	}
	return pc, nil
}
