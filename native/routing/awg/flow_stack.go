package awg

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// FlowStack owns AWG's private userspace TUN. It uses public gVisor APIs and
// numeric destinations only: domain resolution belongs to sing-box's DNS router.
// Unlike the upstream convenience TUN, its packet channel is never closed
// while a notifier can send. Shutdown cancels producers, waits for admitted I/O,
// stops the stack and releases queued views before returning.
type FlowStack struct {
	stack    *stack.Stack
	endpoint *channel.Endpoint
	notify   *channel.NotificationHandle
	mtu      int
	events   chan tun.Event
	packets  chan *buffer.View
	done     chan struct{}
	state    sync.Mutex
	closed   bool
	active   sync.WaitGroup
	once     sync.Once
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewFlowTUN creates an owned private packet interface; both returned values
// share the same idempotent shutdown. It never installs a native OS interface.
func NewFlowTUN(addresses []netip.Addr, mtu int) (tun.Device, *FlowStack, error) {
	if len(addresses) == 0 || mtu < 1280 || mtu > 65535 {
		return nil, nil, errors.New("invalid AWG flow interface")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &FlowStack{ctx: ctx, cancel: cancel, mtu: mtu, events: make(chan tun.Event, 1), packets: make(chan *buffer.View), done: make(chan struct{}),
		endpoint: channel.New(1024, uint32(mtu), ""), stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}, HandleLocal: true})}
	failed := true
	defer func() {
		if failed {
			s.Close()
		}
	}()
	if err := s.stack.CreateNIC(1, s.endpoint); err != nil {
		return nil, nil, errors.New(err.String())
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, nil, errors.New(err.String())
	}
	var has4, has6 bool
	for _, address := range addresses {
		if !address.IsValid() || address.IsUnspecified() {
			return nil, nil, errors.New("invalid AWG flow address")
		}
		protocol := ipv4.ProtocolNumber
		if address.Is6() {
			protocol = ipv6.ProtocolNumber
			has6 = true
		} else {
			has4 = true
		}
		row := tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddrFromSlice(address.AsSlice()).WithPrefix()}
		if err := s.stack.AddProtocolAddress(1, row, stack.AddressProperties{}); err != nil {
			return nil, nil, errors.New(err.String())
		}
	}
	if has4 {
		s.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if has6 {
		s.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	s.notify = s.endpoint.AddNotify(s)
	s.events <- tun.EventUp
	failed = false
	return s, s, nil
}

func (s *FlowStack) begin() bool {
	s.state.Lock()
	defer s.state.Unlock()
	if s.closed {
		return false
	}
	s.active.Add(1)
	return true
}
func (s *FlowStack) File() *os.File           { return nil }
func (s *FlowStack) Name() (string, error)    { return "amnezia-awg-flow", nil }
func (s *FlowStack) MTU() (int, error)        { return s.mtu, nil }
func (s *FlowStack) Events() <-chan tun.Event { return s.events }
func (s *FlowStack) BatchSize() int           { return 1 }
func (s *FlowStack) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-s.done:
		return 0, os.ErrClosed
	default:
	}
	select {
	case <-s.done:
		return 0, os.ErrClosed
	case view := <-s.packets:
		defer view.Release()
		if len(packets) == 0 || len(sizes) == 0 || offset < 0 || offset > len(packets[0]) || view.Size() > len(packets[0])-offset {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(packets[0][offset:], view.AsSlice())
		return 1, nil
	}
}
func (s *FlowStack) Write(packets [][]byte, offset int) (int, error) {
	if !s.begin() {
		return 0, os.ErrClosed
	}
	defer s.active.Done()
	for _, data := range packets {
		if offset < 0 || offset > len(data) {
			return 0, io.ErrShortBuffer
		}
		data = data[offset:]
		if len(data) == 0 {
			continue
		}
		var protocol tcpip.NetworkProtocolNumber
		switch data[0] >> 4 {
		case 4:
			protocol = ipv4.ProtocolNumber
		case 6:
			protocol = ipv6.ProtocolNumber
		default:
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		s.endpoint.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
	return len(packets), nil
}
func (s *FlowStack) WriteNotify() {
	if !s.begin() {
		return
	}
	defer s.active.Done()
	for {
		pkt := s.endpoint.Read()
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		select {
		case s.packets <- view:
		case <-s.done:
			view.Release()
			return
		}
	}
}
func (s *FlowStack) Close() error {
	s.once.Do(func() {
		s.state.Lock()
		s.closed = true
		s.cancel()
		close(s.done)
		s.state.Unlock()
		if s.notify != nil {
			s.endpoint.RemoveNotify(s.notify)
		}
		s.active.Wait()
		s.endpoint.Close()
		s.stack.RemoveNIC(1)
		s.stack.Close()
		s.stack.Wait()
		for {
			select {
			case view := <-s.packets:
				view.Release()
			default:
				close(s.events)
				return
			}
		}
	})
	return nil
}
func flowAddress(address netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	protocol := ipv4.ProtocolNumber
	if address.Addr().Is6() {
		protocol = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(address.Addr().AsSlice()), Port: address.Port()}, protocol
}
func (s *FlowStack) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !s.begin() {
		return nil, net.ErrClosed
	}
	defer s.active.Done()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer cancel()
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	destination, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, errors.New("AWG flow requires a numeric destination")
	}
	full, protocol := flowAddress(destination)
	switch network {
	case "tcp", "tcp4", "tcp6":
		conn, err := gonet.DialContextTCP(ctx, s.stack, full, protocol)
		if err != nil {
			return nil, err
		}
		return conn, nil
	case "udp", "udp4", "udp6":
		conn, err := gonet.DialUDP(s.stack, nil, &full, protocol)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default:
		return nil, errors.New("AWG flow requires TCP or UDP")
	}
}
func (s *FlowStack) ListenTCPAddrPort(address netip.AddrPort) (*gonet.TCPListener, error) {
	if !s.begin() {
		return nil, net.ErrClosed
	}
	defer s.active.Done()
	full, protocol := flowAddress(address)
	return gonet.ListenTCP(s.stack, full, protocol)
}
func (s *FlowStack) ListenUDPAddrPort(address netip.AddrPort) (*gonet.UDPConn, error) {
	if !s.begin() {
		return nil, net.ErrClosed
	}
	defer s.active.Done()
	full, protocol := flowAddress(address)
	return gonet.DialUDP(s.stack, &full, nil, protocol)
}
