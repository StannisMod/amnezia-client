package libXray

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/amnezia-vpn/amnezia-libxray/amnezianativedns"
	M "github.com/amnezia-vpn/amnezia-tun2socks/v2/metadata"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/proxy"
)

var androidDNS struct {
	sync.Mutex
	session    *androidDNSSession
	running    bool
	controller NativeDNSController
	epoch      uint64
}
var androidIPv6Off atomic.Bool

type androidDNSSession struct {
	mu           sync.Mutex
	base         proxy.Proxy
	flows        *nativedns.Flows
	routes       map[netip.AddrPort]androidDNSRoute
	controller   NativeDNSController
	stopping     atomic.Bool
	observerDone chan struct{}
}

// NativeDNSController must protect and bind a socket to the captured original
// Android Network, checking its generation/identity before returning true.
// A false result prevents connect; it never authorizes a default-network retry.
type NativeDNSController interface {
	BindDNS(fd int, networkToken string) bool
	// Enqueue generation-owned cleanup; never synchronously reenter JNI here.
	DNSFailed()
}

func RegisterNativeDNSController(controller NativeDNSController) string {
	androidDNS.Lock()
	defer androidDNS.Unlock()
	if androidDNS.running || androidDNS.session != nil {
		return "native DNS controller still owned"
	}
	androidDNS.controller = controller
	androidDNS.epoch++
	return ""
}

type androidDNSRoute struct {
	Scope        string `json:"scope"`
	NetworkToken string `json:"network_token,omitempty"`
}

type androidDNSBinding struct {
	nativedns.Binding
	androidDNSRoute
}

// PrepareNativeDNS prepares local UDP/TCP listeners in this existing Go
// runtime before Android publishes DNS. An empty configuration is the unchanged
// ON path. Only stopped native engines may replace their DNS generation.
func PrepareNativeDNS(raw string) string {
	androidDNS.Lock()
	defer androidDNS.Unlock()
	if androidDNS.running || androidDNS.session != nil {
		return "native DNS generation still owned"
	}
	if raw == "" {
		androidDNS.controller = nil
		androidIPv6Off.Store(false)
		androidDNS.epoch++
		return ""
	}
	if len(raw) > 65536 {
		return nativedns.ErrScopeUnavailable.Error()
	}
	var config struct {
		Bindings []androidDNSBinding `json:"bindings"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var trailing any
	if decoder.Decode(&config) != nil || decoder.Decode(&trailing) != io.EOF {
		return nativedns.ErrScopeUnavailable.Error()
	}
	s := &androidDNSSession{controller: androidDNS.controller, routes: make(map[netip.AddrPort]androidDNSRoute)}
	bindings := make([]nativedns.Binding, 0, len(config.Bindings))
	for _, binding := range config.Bindings {
		route := binding.androidDNSRoute
		if route.Scope == "" {
			route.Scope = "tunnel"
		}
		switch route.Scope {
		case "direct":
			if s.controller == nil || route.NetworkToken == "" || len(route.NetworkToken) > 512 ||
				strings.ContainsAny(route.NetworkToken, "\x00\r\n") {
				return nativedns.ErrScopeUnavailable.Error()
			}
		case "tunnel":
			if route.NetworkToken != "" {
				return nativedns.ErrScopeUnavailable.Error()
			}
		case "unavailable":
			if !binding.Upstream.Addr().Is6() || route.NetworkToken != "" {
				return nativedns.ErrScopeUnavailable.Error()
			}
		default:
			return nativedns.ErrScopeUnavailable.Error()
		}
		if prior, exists := s.routes[binding.Upstream]; exists && prior != route {
			return nativedns.ErrScopeUnavailable.Error()
		}
		s.routes[binding.Upstream] = route
		bindings = append(bindings, binding.Binding)
	}
	flows, err := nativedns.NewFlows(context.Background(), bindings, s.dial)
	if err != nil {
		return err.Error()
	}
	s.flows = flows
	androidDNS.session = s
	androidDNS.epoch++
	androidIPv6Off.Store(true)
	if s.controller != nil {
		s.observerDone = make(chan struct{})
		go func() {
			defer close(s.observerDone)
			<-s.flows.Done()
			if !s.stopping.Load() {
				s.controller.DNSFailed()
			}
		}()
	}
	return ""
}

// CancelNativeDNS is only for rollback before native engine admission.
func CancelNativeDNS() string {
	androidDNS.Lock()
	if androidDNS.running {
		androidDNS.Unlock()
		return "native DNS engine join required"
	}
	s := androidDNS.session
	epoch := androidDNS.epoch
	if s != nil {
		s.stopping.Store(true)
	}
	androidDNS.Unlock()
	retireNativeDNSSession(s, epoch)
	return ""
}

func quiesceNativeDNS() {
	androidDNS.Lock()
	s := androidDNS.session
	androidDNS.Unlock()
	if s != nil {
		s.flows.Quiesce()
	}
}

func closeNativeDNS() {
	androidDNS.Lock()
	s := androidDNS.session
	epoch := androidDNS.epoch
	if s != nil {
		s.stopping.Store(true)
	}
	androidDNS.Unlock()
	retireNativeDNSSession(s, epoch)
	// Keep the socket fence through Xray's subsequent stop. Only preparation
	// of the next connection may change the user's effective policy.
}

func retireNativeDNSSession(s *androidDNSSession, epoch uint64) {
	if s != nil {
		_ = s.flows.Close()
		if s.observerDone != nil {
			<-s.observerDone
		}
	}
	androidDNS.Lock()
	defer androidDNS.Unlock()
	// Keep admission frozen until listener/exchange AND callback joins.
	// A concurrent idempotent close must never clear a later generation.
	if androidDNS.session == s && androidDNS.epoch == epoch {
		androidDNS.session = nil
		androidDNS.running = false
		androidDNS.controller = nil
	}
}

func (s *androidDNSSession) available() bool {
	if s.stopping.Load() {
		return false
	}
	select {
	case <-s.flows.Done():
		return false
	default:
		return true
	}
}

func nativeDNSProxy(base proxy.Proxy) (proxy.Proxy, error) {
	androidDNS.Lock()
	defer androidDNS.Unlock()
	if androidDNS.running {
		return nil, nativedns.ErrScopeUnavailable
	}
	if androidDNS.session == nil {
		if androidIPv6Off.Load() {
			return nil, nativedns.ErrScopeUnavailable
		}
		androidDNS.running = true
		androidDNS.epoch++
		return base, nil
	}
	s := androidDNS.session
	if !s.available() {
		return nil, nativedns.ErrScopeUnavailable
	}
	s.mu.Lock()
	s.base = base
	s.mu.Unlock()
	// Reserve ownership at engine admission, BEFORE native device creation.
	// Failed/partial starts require confirmed native stop, not blind rollback.
	androidDNS.running = true
	androidDNS.epoch++
	return &androidDNSProxy{Proxy: base, session: s}, nil
}

type androidDNSProxy struct {
	proxy.Proxy
	session *androidDNSSession
}

func (p *androidDNSProxy) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
	if m == nil || !p.session.available() {
		return nil, nativedns.ErrScopeUnavailable
	}
	c, handled, err := p.session.flows.Open(ctx, "tcp", m.DestinationAddrPort())
	if handled {
		return c, err
	}
	return p.Proxy.DialContext(ctx, m) // Unchanged ordinary native IPv4.
}

func (p *androidDNSProxy) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	if m == nil || !p.session.available() {
		return nil, nativedns.ErrScopeUnavailable
	}
	c, handled, err := p.session.flows.OpenPacket(context.Background(), m.DestinationAddrPort())
	if handled {
		return c, err
	}
	return p.Proxy.DialUDP(m) // Unchanged ordinary native IPv4.
}

func (s *androidDNSSession) dial(ctx context.Context, network string, target netip.AddrPort) (net.Conn, error) {
	if !target.Addr().Is4() {
		return nil, nativedns.ErrScopeUnavailable
	}
	route, exists := s.routes[target]
	if !exists {
		return nil, nativedns.ErrScopeUnavailable
	}
	if route.Scope == "direct" {
		if s.controller == nil || (network != "tcp4" && network != "udp4") {
			return nil, nativedns.ErrScopeUnavailable
		}
		dialer := &net.Dialer{Control: func(network, address string, raw syscall.RawConn) error {
			if err := nativeDNSControl(network, address); err != nil {
				return err
			}
			var rejected bool
			if err := raw.Control(func(fd uintptr) {
				rejected = !s.controller.BindDNS(int(fd), route.NetworkToken)
			}); err != nil {
				return err
			}
			if rejected {
				return nativedns.ErrScopeUnavailable
			}
			return nil
		}}
		return dialer.DialContext(ctx, network, target.String())
	}
	if route.Scope != "tunnel" {
		return nil, nativedns.ErrScopeUnavailable
	}
	s.mu.Lock()
	base := s.base
	s.mu.Unlock()
	if base == nil {
		return nil, nativedns.ErrScopeUnavailable
	}
	m := &M.Metadata{DstIP: target.Addr(), DstPort: target.Port(), Network: M.TCP}
	switch network {
	case "tcp4":
		return base.DialContext(ctx, m)
	case "udp4":
		// The actual Android SOCKS adapter exposes the checked contextual
		// ASSOCIATE hook. Do not turn UDP into TCP or spawn an unjoinable dial.
		contextual, ok := base.(interface {
			DialUDPContext(context.Context) (net.PacketConn, error)
		})
		if !ok {
			return nil, nativedns.ErrScopeUnavailable
		}
		pc, err := contextual.DialUDPContext(ctx)
		if err != nil {
			if pc != nil {
				_ = pc.Close()
			}
			return nil, err
		}
		return &androidDNSPacketConn{PacketConn: pc, remote: net.UDPAddrFromAddrPort(target)}, nil
	default:
		return nil, nativedns.ErrScopeUnavailable
	}
}

type androidDNSPacketConn struct {
	net.PacketConn
	remote *net.UDPAddr
}

func (c *androidDNSPacketConn) RemoteAddr() net.Addr        { return c.remote }
func (c *androidDNSPacketConn) Write(p []byte) (int, error) { return c.WriteTo(p, c.remote) }
func (c *androidDNSPacketConn) Read(p []byte) (int, error) {
	for {
		n, from, err := c.ReadFrom(p)
		if err != nil {
			return n, err
		}
		if from != nil && from.String() == c.remote.String() {
			return n, nil
		}
	}
}

func nativeDNSControl(network, address string) error {
	if !androidIPv6Off.Load() {
		return nil
	}
	if strings.HasSuffix(network, "6") {
		return nativedns.ErrScopeUnavailable
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nativedns.ErrScopeUnavailable
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return nativedns.ErrScopeUnavailable
	}
	return nil
}
