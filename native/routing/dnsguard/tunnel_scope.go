package dnsguard

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/nativedns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// NewTunnelPacketSession uses the DNS capture's EXISTING stack for selected DNS
// through a native engine. source must be its original IPv4 tunnel address.
// writeTunnel must copy/enqueue onto that engine's I/O thread, not write to the
// OS TUN. Like PacketCallbacks, it must not synchronously retire its own owner.
// The adapter must offer decrypted engine packets to FeedTunnel before its
// original TUN writer. No OS Network.bindSocket or application UID change is
// involved. Kernel sockets only reserve ports; they never listen or connect.
func NewTunnelPacketSession(parent context.Context, address, source netip.Addr, mtu int,
	server nativedns.EncryptedServer, writeTunnel func([]byte) bool, callbacks PacketCallbacks) (*PacketSession, error) {
	reject := func() (*PacketSession, error) {
		if callbacks.Release != nil {
			callbacks.Release()
		}
		return nil, nativedns.ErrScopeUnavailable
	}
	if mtu < 68 || mtu > 65535 || !address.Is4() || !source.Is4() || !source.IsGlobalUnicast() ||
		source.IsLoopback() || source == address || !server.Address.Addr().Is4() ||
		server.Address.Addr() == source || server.Address.Addr() == address || writeTunnel == nil {
		return reject()
	}
	scope := &tunnelPacketScope{source: source, upstream: server.Address, mtu: uint32(mtu),
		write: writeTunnel, leases: make(map[tunnelPort]context.Context)}
	exchange, err := nativedns.SelectedResolver(server, scope.dial, nil)
	if err != nil {
		return reject()
	}
	return newPacketSessionScoped(parent, address, callbacks, exchange, scope)
}

type tunnelPacketScope struct {
	endpoint  *packetEndpoint
	source    netip.Addr
	upstream  netip.AddrPort
	mtu       uint32
	write     func([]byte) bool
	failed    func()
	mu        sync.Mutex
	leases    map[tunnelPort]context.Context
	fragments map[tunnelFragment]tunnelFragmentLease
	writing   int
}

type tunnelFragment struct {
	protocol byte
	id       uint16
}

type tunnelFragmentLease struct {
	ctx     context.Context
	expires time.Time
}

type tunnelPort struct {
	protocol byte
	port     uint16
}

type tunnelConn struct {
	net.Conn
	reservation *os.File
	scope       *tunnelPacketScope
	key         tunnelPort
	once        sync.Once
}

type tunnelUDPConn struct{ *tunnelConn }

func (c *tunnelUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.Conn.(net.PacketConn).ReadFrom(p)
}

func (c *tunnelUDPConn) WriteTo(p []byte, address net.Addr) (int, error) {
	return c.Conn.(net.PacketConn).WriteTo(p, address)
}

func (c *tunnelConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.scope.mu.Lock()
		delete(c.scope.leases, c.key)
		c.scope.mu.Unlock()
		_ = c.reservation.Close()
	})
	return err
}

func (s *tunnelPacketScope) dial(ctx context.Context, network string, upstream netip.AddrPort) (net.Conn, error) {
	if upstream != s.upstream || (network != "udp4" && network != "tcp4") || ctx.Err() != nil {
		return nil, nativedns.ErrScopeUnavailable
	}
	if !s.endpoint.begin() {
		return nil, net.ErrClosed
	}
	defer s.endpoint.active.Done()
	reservation, port, err := reserveTunnelPort(network)
	if err != nil {
		return nil, err
	}
	key := tunnelPort{17, port}
	if network == "tcp4" {
		key.protocol = 6
	}
	s.mu.Lock()
	_, exists := s.leases[key]
	if exists || len(s.leases) >= 128 {
		s.mu.Unlock()
		reservation.Close()
		return nil, nativedns.ErrScopeUnavailable
	}
	s.leases[key] = ctx
	s.mu.Unlock()
	local := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(s.source.AsSlice()), Port: port}
	remote := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(upstream.Addr().AsSlice()), Port: upstream.Port()}
	var conn net.Conn
	if network == "udp4" {
		conn, err = gonet.DialUDP(s.endpoint.stack, &local, &remote, ipv4.ProtocolNumber)
	} else {
		conn, err = gonet.DialTCPWithBind(ctx, s.endpoint.stack, local, remote, ipv4.ProtocolNumber)
	}
	if err != nil {
		s.mu.Lock()
		delete(s.leases, key)
		s.mu.Unlock()
		reservation.Close()
		return nil, err
	}
	c := &tunnelConn{Conn: conn, reservation: reservation, scope: s, key: key}
	if ctx.Err() != nil {
		c.Close()
		return nil, ctx.Err()
	}
	if network == "udp4" {
		return &tunnelUDPConn{c}, nil
	}
	return c, nil
}

// tunnelIPv4 validates only the IP envelope. gVisor validates checksums,
// reassembles fragments and validates transport state in the original stack.
func tunnelIPv4(packet []byte) (header int, fragmented bool, ok bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return
	}
	header = int(packet[0]&15) * 4
	if header < 20 || header > len(packet) ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
		(packet[9] != 6 && packet[9] != 17) {
		return
	}
	fragmented = binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0
	ok = fragmented || len(packet) >= header+8
	return
}

func (s *tunnelPacketScope) active(protocol byte, port uint16, fragmented bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !fragmented {
		ctx, exists := s.leases[tunnelPort{protocol, port}]
		return exists && ctx.Err() == nil
	}
	for key, ctx := range s.leases {
		if key.protocol == protocol && ctx.Err() == nil {
			return true
		}
	}
	return false
}

func (s *tunnelPacketScope) beginOutput(protocol byte, port uint16, fragmented bool) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !fragmented {
		ctx := s.leases[tunnelPort{protocol, port}]
		if ctx != nil && ctx.Err() == nil {
			s.writing++
			return ctx
		}
		return nil
	}
	for key, ctx := range s.leases {
		if key.protocol == protocol && ctx.Err() == nil {
			s.writing++
			return ctx
		}
	}
	return nil
}

func (s *tunnelPacketScope) idle() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writing == 0 && len(s.leases) == 0
}

func (s *tunnelPacketScope) incoming(packet []byte) (copyForReassembly, consume bool) {
	header, fragmented, ok := tunnelIPv4(packet)
	if !ok || netip.AddrFrom4([4]byte(packet[12:16])) != s.upstream.Addr() ||
		netip.AddrFrom4([4]byte(packet[16:20])) != s.source {
		return false, false
	}
	if fragmented {
		return s.incomingFragment(packet, header)
	}
	if binary.BigEndian.Uint16(packet[header:header+2]) != s.upstream.Port() {
		return false, false
	}
	port := binary.BigEndian.Uint16(packet[header+2 : header+4])
	owned := s.active(packet[9], port, false)
	return owned, owned
}

func (s *tunnelPacketScope) incomingFragment(packet []byte, header int) (mirror, consume bool) {
	key := tunnelFragment{packet[9], binary.BigEndian.Uint16(packet[4:6])}
	first := binary.BigEndian.Uint16(packet[6:8])&0x1fff == 0
	now := time.Now()
	s.mu.Lock()
	if first {
		if len(packet) < header+8 {
			s.mu.Unlock()
			return false, false
		}
		port := binary.BigEndian.Uint16(packet[header+2 : header+4])
		ctx, owned := s.leases[tunnelPort{packet[9], port}]
		if binary.BigEndian.Uint16(packet[header:header+2]) != s.upstream.Port() ||
			!owned || ctx.Err() != nil {
			delete(s.fragments, key)
			s.mu.Unlock()
			return false, false
		}
		if s.fragments == nil {
			s.fragments = make(map[tunnelFragment]tunnelFragmentLease)
		}
		for id, lease := range s.fragments {
			if !now.Before(lease.expires) {
				delete(s.fragments, id)
			}
		}
		if _, exists := s.fragments[key]; exists || len(s.fragments) < 1024 {
			s.fragments[key] = tunnelFragmentLease{ctx, now.Add(30 * time.Second)}
		}
		s.mu.Unlock()
		// NEVER give the kernel the first fragment of a leased DNS flow.
		// In particular a bound-but-unconnected TCP reservation would reply
		// RST if allowed to reassemble our private stack's TCP response.
		return true, true
	}
	if lease, known := s.fragments[key]; known && now.Before(lease.expires) {
		s.mu.Unlock()
		return lease.ctx.Err() == nil, true
	}
	s.mu.Unlock()
	// An out-of-order unidentified fragment is copied only for reassembly,
	// and still follows its original native/kernel path. A later DNS-owned
	// first fragment is consumed, preventing duplicate kernel reassembly.
	// An application-owned first fragment is NOT injected at all.
	return s.active(packet[9], 0, true), false
}

func (s *tunnelPacketScope) output(packet []byte) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 ||
		netip.AddrFrom4([4]byte(packet[12:16])) != s.source {
		return false // Original alias replies still go to the original TUN writer.
	}
	header, fragmented, ok := tunnelIPv4(packet)
	if !ok || netip.AddrFrom4([4]byte(packet[16:20])) != s.upstream.Addr() {
		return true // Unknown source-owned output never reaches kernel/default routing.
	}
	var port uint16
	if !fragmented {
		if binary.BigEndian.Uint16(packet[header+2:header+4]) != s.upstream.Port() {
			return true
		}
		port = binary.BigEndian.Uint16(packet[header : header+2])
	}
	if ctx := s.beginOutput(packet[9], port, fragmented); ctx != nil {
		defer func() {
			s.mu.Lock()
			s.writing--
			s.mu.Unlock()
		}()
		if !s.write(packet) && ctx.Err() == nil {
			s.failed()
		}
	}
	return true
}

// FeedTunnel leaves all unowned decrypted native packets untouched. It mirrors
// unidentified selected-peer IP fragments, but consumes a leased DNS flow's
// first fragment so the kernel cannot also reassemble/reset that private flow.
func (s *PacketSession) FeedTunnel(packet []byte) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.tunnel == nil {
		return 0
	}
	mirror, consume := s.tunnel.incoming(packet)
	if !mirror && !consume {
		return 0
	}
	if s.closed || s.failed.Load() {
		if consume {
			return -1
		}
		return 0
	}
	if mirror {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), packet...)),
		})
		s.tunnel.endpoint.link.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()
	}
	if consume {
		return 1
	}
	return 0
}
