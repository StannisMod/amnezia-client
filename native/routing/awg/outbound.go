package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const Type = "amneziawg"

// Register installs AWG into the same Go module/runtime as sing-box. It does
// not replace upstream WireGuard or change any other app protocol backend.
func Register(r *outbound.Registry, listen ListenUnderlay) {
	outbound.Register[Config](r, Type, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, c Config) (adapter.Outbound, error) {
		if listen == nil {
			return nil, errors.New("AWG requires a protected underlay")
		}
		if _, e := c.uapi(); e != nil {
			return nil, e
		}
		return &Outbound{Adapter: outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil), ctx: ctx, config: c, listen: listen, dns: service.FromContext[adapter.DNSRouter](ctx)}, nil
	})
}

type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	config    Config
	listen    ListenUnderlay
	dns       adapter.DNSRouter
	mu        sync.RWMutex
	transport *Transport
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	t, e := New(o.ctx, o.config, o.listen)
	if e != nil {
		return e
	}
	o.mu.Lock()
	o.transport = t
	o.mu.Unlock()
	scope.Add(func() error { o.mu.Lock(); o.transport = nil; o.mu.Unlock(); return t.Close() })
	return nil
}
func (o *Outbound) get() (*Transport, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.transport == nil {
		return nil, net.ErrClosed
	}
	return o.transport, nil
}

func (o *Outbound) Stats() (Stats, error) {
	t, err := o.get()
	if err != nil {
		return Stats{}, err
	}
	return t.Stats()
}

func (o *Outbound) addresses(ctx context.Context, d M.Socksaddr) ([]netip.Addr, error) {
	if d.IsIP() {
		return []netip.Addr{d.Addr}, nil
	}
	return o.dns.Lookup(ctx, d.Fqdn, adapter.DNSQueryOptions{})
}

func (o *Outbound) DialContext(ctx context.Context, network string, d M.Socksaddr) (net.Conn, error) {
	t, e := o.get()
	if e != nil {
		return nil, e
	}
	if network != N.NetworkTCP && network != N.NetworkUDP {
		return nil, errors.New("AWG supports TCP and UDP flows")
	}
	addresses, e := o.addresses(ctx, d)
	if e != nil {
		return nil, e
	}
	for _, a := range addresses {
		var c net.Conn
		c, e = t.DialContext(ctx, network, netip.AddrPortFrom(a, d.Port).String())
		if e == nil {
			return c, nil
		}
	}
	return nil, errors.New("AWG destination unavailable")
}
func (o *Outbound) ListenPacket(ctx context.Context, d M.Socksaddr) (net.PacketConn, error) {
	t, e := o.get()
	if e != nil {
		return nil, e
	}
	addresses, e := o.addresses(ctx, d)
	if e != nil {
		return nil, e
	}
	if len(addresses) == 0 {
		return nil, errors.New("AWG destination has no addresses")
	}
	a := addresses[0]
	pc, e := t.ListenPacket(ctx, a)
	if e != nil {
		return nil, e
	}
	if d.IsDomain() {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(pc), M.SocksaddrFrom(a, d.Port), d), nil
	}
	return pc, nil
}
