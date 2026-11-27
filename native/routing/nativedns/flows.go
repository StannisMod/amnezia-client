package nativedns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
)

// Flows attaches DNS to an existing native flow owner. It never opens or reads
// a TUN. The owner routes only its configured DNS destinations here and keeps
// ordinary IPv4 flows in its original backend.
type Flows struct {
	ctx       context.Context
	cancel    context.CancelFunc
	endpoints map[netip.AddrPort]*flowEndpoint
	mu        sync.Mutex
	clients   map[*flowConn]struct{}
	closed    bool
	once      sync.Once
}

type flowEndpoint struct {
	local    netip.AddrPort
	frontend *SocketFrontend
}

// NewFlows prepares both transports for every resolver occurrence before the
// caller publishes managed DNS. dial must be the native owner's scoped dialer,
// not an OS/default dialer. Binding interface fields are intentionally refused:
// they belong to the desktop socket adapter, not a native proxy's DNS scope.
func NewFlows(parent context.Context, bindings []Binding, dial Dial) (*Flows, error) {
	if parent == nil || parent.Err() != nil || dial == nil || len(bindings) == 0 || len(bindings) > 16 {
		return nil, ErrScopeUnavailable
	}
	seen := make(map[netip.AddrPort]bool)
	for _, b := range bindings {
		if !b.Endpoint.IsValid() || !b.Endpoint.Addr().Is4() ||
			!b.Endpoint.Addr().IsGlobalUnicast() || b.Endpoint.Port() != 53 ||
			seen[b.Endpoint] || b.InterfaceName != "" || b.InterfaceIndex != 0 {
			return nil, ErrScopeUnavailable
		}
		seen[b.Endpoint] = true
	}
	for _, b := range bindings {
		if seen[b.Upstream] {
			return nil, ErrScopeUnavailable
		}
	}
	ctx, cancel := context.WithCancel(parent)
	f := &Flows{ctx: ctx, cancel: cancel, endpoints: make(map[netip.AddrPort]*flowEndpoint),
		clients: make(map[*flowConn]struct{})}
	fail := func() (*Flows, error) { _ = f.Close(); return nil, ErrScopeUnavailable }
	for _, b := range bindings {
		exchange, err := SelectedResolver(EncryptedServer{Address: b.Upstream,
			Transport: b.Transport, ServerName: b.ServerName, HTTPSURL: b.HTTPSURL}, dial, nil)
		if err != nil {
			return fail()
		}
		tcp, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return fail()
		}
		local := tcp.Addr().(*net.TCPAddr).AddrPort()
		udp, err := net.ListenPacket("udp4", local.String())
		if err != nil {
			_ = tcp.Close()
			return fail()
		}
		frontend, err := NewSocket(ctx, udp, tcp, exchange)
		if err != nil {
			return fail()
		}
		f.endpoints[b.Endpoint] = &flowEndpoint{local: local, frontend: frontend}
	}
	// Publish the immutable map only after preparation; failure observers do
	// not race construction/rollback.
	for _, endpoint := range f.endpoints {
		go func(e *flowEndpoint) {
			<-e.frontend.Done()
			cancel()
		}(endpoint)
	}
	go func() { <-ctx.Done(); _ = f.Close() }()
	return f, nil
}

// Open consumes only configured managed DNS destinations and IPv6. handled
// false authorizes the caller's unchanged IPv4 backend, not a default dialer.
// Never delegate an IPv6 target, including an IPv6-only DNS upstream.
func (f *Flows) Open(ctx context.Context, network string, target netip.AddrPort) (conn net.Conn, handled bool, err error) {
	if !target.IsValid() || !target.Addr().Is4() {
		return nil, true, ErrScopeUnavailable
	}
	e, exists := f.endpoints[target]
	if !exists {
		return nil, false, nil
	}
	if ctx == nil || (network != "tcp" && network != "udp") {
		return nil, true, ErrScopeUnavailable
	}
	f.mu.Lock()
	if f.closed || f.ctx.Err() != nil {
		f.mu.Unlock()
		return nil, true, ErrScopeUnavailable
	}
	f.mu.Unlock()
	// This dial is ONLY to our already prepared loopback listener. Upstream
	// forwarding is exclusively the explicit native dial supplied to NewFlows.
	c, err := (&net.Dialer{}).DialContext(ctx, network+"4", e.local.String())
	if err != nil {
		return nil, true, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.ctx.Err() != nil {
		_ = c.Close()
		return nil, true, ErrScopeUnavailable
	}
	client := &flowConn{Conn: c, owner: f}
	f.clients[client] = struct{}{}
	return client, true, nil
}

// OpenPacket retains the native engine's PacketConn contract and validates
// every datagram's destination. An association cannot change resolver/scope.
func (f *Flows) OpenPacket(ctx context.Context, target netip.AddrPort) (net.PacketConn, bool, error) {
	c, handled, err := f.Open(ctx, "udp", target)
	if err != nil || !handled {
		return nil, handled, err
	}
	return &flowPacketConn{Conn: c, target: target}, true, nil
}

type flowPacketConn struct {
	net.Conn
	target netip.AddrPort
}

func (c *flowPacketConn) WriteTo(packet []byte, to net.Addr) (int, error) {
	if to == nil || to.String() != c.target.String() {
		return 0, ErrScopeUnavailable
	}
	return c.Write(packet)
}

func (c *flowPacketConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	n, err := c.Read(packet)
	return n, net.UDPAddrFromAddrPort(c.target), err
}

type flowConn struct {
	net.Conn
	owner *Flows
	once  sync.Once
	err   error
}

func (c *flowConn) closeTransport() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}

func (c *flowConn) Close() error {
	err := c.closeTransport()
	c.owner.mu.Lock()
	delete(c.owner.clients, c)
	c.owner.mu.Unlock()
	return err
}

// Quiesce cancels and joins all upstream DNS exchanges but preserves local
// UDP/TCP NODATA/SERVFAIL until the native owner retires capture.
func (f *Flows) Quiesce() {
	for _, e := range f.endpoints {
		e.frontend.quiesceBegin()
	}
	for _, e := range f.endpoints {
		e.frontend.forwardDone.Wait()
	}
}

func (f *Flows) Done() <-chan struct{} { return f.ctx.Done() }

func (f *Flows) Close() error {
	var result error
	f.once.Do(func() {
		f.cancel()
		f.mu.Lock()
		f.closed = true
		for client := range f.clients {
			result = errors.Join(result, client.closeTransport())
		}
		f.clients = make(map[*flowConn]struct{})
		f.mu.Unlock()
		for _, e := range f.endpoints {
			result = errors.Join(result, e.frontend.Close())
		}
	})
	return result
}
