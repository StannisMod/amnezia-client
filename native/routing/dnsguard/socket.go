package dnsguard

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// SocketFrontend is a DNS-only local endpoint for native desktop adapters
// whose packet reader belongs to the kernel/native VPN process. It creates no
// TUN or flow proxy and changes no OS resolver, route or upstream policy.
// The adapter must publish its settings only after NewSocket succeeds, retain
// original resolver scope in Exchange, and fail closed when Done closes.
type SocketFrontend struct {
	ctx      context.Context
	cancel   context.CancelFunc
	udp      *dns.Server
	tcp      *dns.Server
	packet   net.PacketConn
	listener net.Listener
	done     sync.WaitGroup
	once     sync.Once
}

// NewSocket consumes both listeners on success and failure. They must be bound
// to the same explicit, uniquely assigned local IPv4 endpoint, never wildcard
// or IPv6. Native link-scoped system resolvers need an address assigned to that
// link; loopback alone cannot preserve that scope. Binding
// and resolver publication remain an adapter transaction, not implicit fallback.
func NewSocket(parent context.Context, packet net.PacketConn, listener net.Listener, exchange Exchange) (*SocketFrontend, error) {
	fail := func() (*SocketFrontend, error) {
		if packet != nil {
			_ = packet.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		return nil, errors.New("DNS guard requires matched assigned IPv4 listeners and scoped exchange")
	}
	if parent == nil || packet == nil || listener == nil || exchange == nil {
		return fail()
	}
	if parent.Err() != nil {
		return fail()
	}
	udp, okUDP := packet.LocalAddr().(*net.UDPAddr)
	tcp, okTCP := listener.Addr().(*net.TCPAddr)
	if !okUDP || !okTCP || udp.IP.To4() == nil || tcp.IP.To4() == nil ||
		!udp.IP.Equal(tcp.IP) ||
		udp.Port <= 0 || udp.Port != tcp.Port {
		return fail()
	}
	if !assignedIPv4(udp.IP) {
		return fail()
	}
	ctx, cancel := context.WithCancel(parent)
	f := &SocketFrontend{ctx: ctx, cancel: cancel, packet: packet, listener: listener}
	handler := newSocketHandler(ctx, exchange)
	f.udp = &dns.Server{PacketConn: packet, Handler: handler, UDPSize: 4096,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	f.tcp = &dns.Server{Listener: listener, Handler: handler, MaxTCPQueries: 128,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	ready := make(chan struct{}, 2)
	f.udp.NotifyStartedFunc = func() { ready <- struct{}{} }
	f.tcp.NotifyStartedFunc = func() { ready <- struct{}{} }
	f.done.Add(2)
	serve := func(server *dns.Server) {
		defer f.done.Done()
		_ = server.ActivateAndServe()
		cancel()
	}
	go serve(f.udp)
	go serve(f.tcp)
	for i := 0; i < 2; i++ {
		select {
		case <-ready:
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		}
	}
	go func() { <-ctx.Done(); _ = f.Close() }()
	return f, nil
}

func newSocketHandler(ctx context.Context, exchange Exchange) dns.Handler {
	policy := newHandler(ctx, exchange)
	return dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		// An address on a native VPN interface must not turn this process into
		// a recursive service for remote VPN peers. Only local source addresses
		// may use the OS resolver endpoint; do not even reflect an error to
		// a non-local UDP source.
		host, _, err := net.SplitHostPort(w.RemoteAddr().String())
		source := net.ParseIP(host)
		if err != nil || source.To4() == nil || (!source.IsLoopback() && !assignedIPv4(source)) {
			return
		}
		policy.ServeDNS(w, request)
	})
}

// Test exact address ownership, not merely membership in a connected subnet.
// Ambiguous or unavailable native interface state is not a fallback to lo or
// to a wildcard service. The adapter still owns alias lifetime and publication.
func assignedIPv4(ip net.IP) bool {
	if ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() ||
		(!ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()) {
		return false
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	count := 0
	for _, address := range addresses {
		local, _, err := net.ParseCIDR(address.String())
		if err == nil && local.Equal(ip) {
			count++
		}
	}
	return count == 1
}

func (f *SocketFrontend) Done() <-chan struct{} { return f.ctx.Done() }

// Close cancels scoped exchanges before joining handlers and native listeners.
// Never call it inline from Exchange; request cancellation instead.
func (f *SocketFrontend) Close() error {
	f.once.Do(func() {
		f.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.udp.ShutdownContext(ctx)
		_ = f.tcp.ShutdownContext(ctx)
		_ = f.packet.Close()
		_ = f.listener.Close()
		f.done.Wait()
	})
	return nil
}
