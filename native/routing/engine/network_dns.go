package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

const borrowedDNSVPNType = "amnezia-dns-vpn"

type runtimeHost struct{ underlay Underlay }
type borrowedDNSVPNState struct{ outbound adapter.Outbound }
type borrowedDNSVPN struct {
	outbound.Adapter
	delegate adapter.Outbound
}

func (b *borrowedDNSVPN) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (b *borrowedDNSVPN) DialContext(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
	return b.delegate.DialContext(ctx, n, d)
}
func (b *borrowedDNSVPN) ListenPacket(ctx context.Context, d M.Socksaddr) (net.PacketConn, error) {
	return b.delegate.ListenPacket(ctx, d)
}
func registerBorrowedDNSVPN(r *outbound.Registry) {
	outbound.Register[struct{}](r, borrowedDNSVPNType, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Outbound, error) {
		state := service.FromContext[*borrowedDNSVPNState](ctx)
		if state == nil || state.outbound == nil {
			return nil, errors.New("missing existing VPN for DNS")
		}
		return &borrowedDNSVPN{Adapter: outbound.NewAdapter(borrowedDNSVPNType, tag, []string{"tcp", "udp"}, nil), delegate: state.outbound}, nil
	})
}

type dnsGeneration struct {
	box        interface{ Close() error }
	router     adapter.DNSRouter
	ctx        context.Context
	cancel     context.CancelFunc
	stopParent func() bool
	once       sync.Once
}

func (g *dnsGeneration) close() { g.once.Do(func() { g.cancel(); g.stopParent(); g.box.Close() }) }

// DNS-only projection: no capture reader, no private VPN device/netstack, no
// second FakeIP database. DNS connections borrow the live VPN dialer; their
// lifecycle cannot close it or application connections owned by the main Box.
func newDNSGeneration(parent context.Context, compiled []byte, host Underlay, platform adapter.PlatformInterface, vpn adapter.Outbound) (*dnsGeneration, error) {
	var options map[string]any
	if json.Unmarshal(compiled, &options) != nil {
		return nil, errors.New("invalid network DNS configuration")
	}
	settings, ok := options["dns"].(map[string]any)
	if !ok {
		return nil, errors.New("missing network DNS settings")
	}
	servers, ok := settings["servers"].([]any)
	if !ok {
		return nil, errors.New("missing network DNS servers")
	}
	var realServers []any
	for _, value := range servers {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid network DNS server")
		}
		if row["type"] != "fakeip" {
			realServers = append(realServers, row)
		}
	}
	settings["servers"] = realServers
	var realRules []any
	rules, ok := settings["rules"].([]any)
	if !ok {
		return nil, errors.New("missing network DNS rules")
	}
	for _, value := range rules {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid network DNS rule")
		}
		if row["server"] != "fake" {
			realRules = append(realRules, row)
		}
	}
	settings["rules"] = realRules
	rows, ok := options["outbounds"].([]any)
	if !ok {
		return nil, errors.New("missing network DNS paths")
	}
	for i, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid network DNS path")
		}
		if row["tag"] == "vpn" {
			rows[i] = map[string]any{"type": borrowedDNSVPNType, "tag": "vpn"}
		} else if row["type"] != "direct" {
			return nil, errors.New("network DNS projection cannot create another VPN")
		}
	}
	options["outbounds"] = rows
	delete(options, "inbounds")
	delete(options, "experimental")
	options["route"] = map[string]any{"final": "vpn"}
	raw, err := json.Marshal(options)
	if err != nil {
		return nil, errors.New("invalid network DNS projection")
	}
	// A fresh registry is mandatory. Inheriting the main context's registry
	// would overwrite its managers and could turn DNS close into flow close.
	ctx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(parent, cancel)
	ctx = Context(ctx, host)
	if platform != nil {
		ctx = service.ContextWith[adapter.PlatformInterface](ctx, platform)
	}
	ctx = service.ContextWith[*borrowedDNSVPNState](ctx, &borrowedDNSVPNState{outbound: vpn})
	instance, err := New(ctx, raw)
	if err != nil {
		cancel()
		stop()
		return nil, errors.New("network DNS initialization failed")
	}
	if err = instance.Start(); err != nil {
		cancel()
		stop()
		return nil, errors.New("network DNS startup failed")
	}
	return &dnsGeneration{box: instance, router: service.FromContext[adapter.DNSRouter](ctx), ctx: ctx, cancel: cancel, stopParent: stop}, nil
}

type networkDNSProxy struct {
	mu      sync.RWMutex
	current *dnsGeneration
	version uint64
}

func (p *networkDNSProxy) freeze() uint64 {
	p.mu.Lock()
	old := p.current
	p.current = nil
	p.version++
	version := p.version
	p.mu.Unlock()
	if old != nil {
		old.close()
	}
	return version
}
func (p *networkDNSProxy) replace(g *dnsGeneration, version uint64) bool {
	p.mu.Lock()
	if p.version != version {
		p.mu.Unlock()
		g.close()
		return false
	}
	old := p.current
	p.current = g
	p.mu.Unlock()
	if old != nil {
		old.close()
	}
	return true
}
func (p *networkDNSProxy) exchange(caller context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	p.mu.RLock()
	g := p.current
	p.mu.RUnlock()
	if g == nil {
		return nil, errors.New("network DNS is waiting for a valid snapshot")
	}
	// Carry cancellation/deadline, not the caller's main-Box service registry.
	ctx, cancel := context.WithCancel(g.ctx)
	if deadline, ok := caller.Deadline(); ok {
		cancel()
		ctx, cancel = context.WithDeadline(g.ctx, deadline)
	}
	stop := context.AfterFunc(caller, cancel)
	defer func() { stop(); cancel() }()
	// The service registry belongs to the DNS generation, but application
	// identity belongs to the original flow. Dropping it would make every
	// per-app query look like an unknown owner (and select VPN DNS).
	if metadata := adapter.ContextFrom(caller); metadata != nil {
		copy := *metadata
		copy.ResetRuleCache()
		ctx = adapter.WithContext(ctx, &copy)
	}
	response, err := g.router.Exchange(ctx, message, adapter.DNSQueryOptions{})
	p.mu.RLock()
	valid := p.current == g
	p.mu.RUnlock()
	if !valid {
		return nil, errors.New("network DNS generation changed")
	}
	return response, err
}

type networkDNSRegistry struct{ adapter.DNSTransportRegistry }

func (r *networkDNSRegistry) CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag, kind string, options any) (adapter.DNSTransport, error) {
	p := service.FromContext[*networkDNSProxy](ctx)
	if p == nil || (kind != "udp" && kind != "tcp" && kind != "tls" && kind != "https") {
		return r.DNSTransportRegistry.CreateDNSTransport(ctx, logger, tag, kind, options)
	}
	return &networkDNSTransport{TransportAdapter: dns.NewTransportAdapter(kind, tag, nil), proxy: p}, nil
}

type networkDNSTransport struct {
	dns.TransportAdapter
	proxy *networkDNSProxy
}

func (t *networkDNSTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (t *networkDNSTransport) Reset()                                         {}
func (t *networkDNSTransport) Exchange(ctx context.Context, m *mDNS.Msg) (*mDNS.Msg, error) {
	return t.proxy.exchange(ctx, m)
}
func (t *networkDNSTransport) ExchangeAsync(ctx context.Context, m *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { r, e := t.Exchange(ctx, m); callback(r, e) }()
}
