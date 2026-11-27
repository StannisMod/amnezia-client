package dnsguard

import (
	"errors"
	"io"
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
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// packetEndpoint owns DNS capture and optionally exact leased DNS-only native
// upstream flows. It has no application dialer, path migration machinery, OS
// interface or independent TUN reader. Native adapters dispatch matching DNS
// packets into it from their existing reader/engine.
type packetEndpoint struct {
	stack      *stack.Stack
	link       *channel.Endpoint
	notify     *channel.NotificationHandle
	address    netip.Addr
	protocol   tcpip.NetworkProtocolNumber
	done       chan struct{}
	outputWake chan struct{}
	outputDone chan struct{}
	packets    chan *buffer.View
	events     chan tun.Event
	mu         sync.Mutex
	closed     bool
	active     sync.WaitGroup
	once       sync.Once
	tunnel     *tunnelPacketScope
}

func newPacketEndpoint(address netip.Addr) (*packetEndpoint, error) {
	return newPacketEndpointScoped(address, nil)
}

func newPacketEndpointScoped(address netip.Addr, tunnel *tunnelPacketScope) (*packetEndpoint, error) {
	if !address.IsGlobalUnicast() || address.Zone() != "" {
		return nil, errors.New("DNS capture requires an unicast address")
	}
	mtu := uint32(1280)
	if tunnel != nil {
		mtu = tunnel.mtu
	}
	s := &packetEndpoint{
		address: address, protocol: ipv4.ProtocolNumber, tunnel: tunnel,
		done: make(chan struct{}), outputWake: make(chan struct{}, 1),
		outputDone: make(chan struct{}), packets: make(chan *buffer.View),
		events: make(chan tun.Event, 1),
		link:   channel.New(1024, mtu, ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
			HandleLocal:        true,
		}),
	}
	if tunnel != nil {
		tunnel.endpoint = s
	}
	go s.runOutput()
	fail := func(err tcpip.Error) (*packetEndpoint, error) {
		_ = s.Close()
		return nil, errors.New(err.String())
	}
	if err := s.stack.CreateNIC(1, s.link); err != nil {
		return fail(err)
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fail(err)
	}
	subnet := header.IPv4EmptySubnet
	if address.Is6() {
		s.protocol = ipv6.ProtocolNumber
		subnet = header.IPv6EmptySubnet
	}
	row := tcpip.ProtocolAddress{Protocol: s.protocol,
		AddressWithPrefix: tcpip.AddrFromSlice(address.AsSlice()).WithPrefix()}
	if err := s.stack.AddProtocolAddress(1, row, stack.AddressProperties{}); err != nil {
		return fail(err)
	}
	if tunnel != nil {
		if err := s.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(tunnel.source.AsSlice()).WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			return fail(err)
		}
	}
	s.stack.AddRoute(tcpip.Route{Destination: subnet, NIC: 1})
	s.notify = s.link.AddNotify(s)
	s.events <- tun.EventUp
	return s, nil
}

func (s *packetEndpoint) begin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.active.Add(1)
	return true
}

func (s *packetEndpoint) File() *os.File           { return nil }
func (s *packetEndpoint) Name() (string, error)    { return "amnezia-native-dns", nil }
func (s *packetEndpoint) MTU() (int, error)        { return int(s.link.MTU()), nil }
func (s *packetEndpoint) Events() <-chan tun.Event { return s.events }
func (s *packetEndpoint) BatchSize() int           { return 1 }

func (s *packetEndpoint) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	if !s.begin() {
		return 0, os.ErrClosed
	}
	defer s.active.Done()
	select {
	case <-s.done:
		return 0, os.ErrClosed
	case view := <-s.packets:
		defer view.Release()
		if len(packets) == 0 || len(sizes) == 0 || offset < 0 ||
			offset > len(packets[0]) || view.Size() > len(packets[0])-offset {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(packets[0][offset:], view.AsSlice())
		return 1, nil
	}
}

func (s *packetEndpoint) Write(packets [][]byte, offset int) (int, error) {
	if !s.begin() {
		return 0, os.ErrClosed
	}
	defer s.active.Done()
	for i, data := range packets {
		if offset < 0 || offset > len(data) {
			return i, io.ErrShortBuffer
		}
		data = data[offset:]
		// Even a misbehaving native caller cannot turn this DNS-only endpoint
		// into an alternate full-flow stack or deliver another address's I/O.
		if !dnsDestination(data, s.address) {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		s.link.InjectInbound(s.protocol, pkt)
		pkt.DecRef()
	}
	return len(packets), nil
}

func (s *packetEndpoint) WriteNotify() {
	select {
	case s.outputWake <- struct{}{}:
	case <-s.done:
	default:
	}
}

func (s *packetEndpoint) runOutput() {
	defer close(s.outputDone)
	for {
		select {
		case <-s.done:
			return
		case <-s.outputWake:
		}
		for {
			pkt := s.link.Read()
			if pkt == nil {
				break
			}
			view := pkt.ToView()
			pkt.DecRef()
			if s.tunnel != nil && s.tunnel.output(view.AsSlice()) {
				view.Release()
				continue
			}
			select {
			case s.packets <- view:
			case <-s.done:
				view.Release()
				return
			}
		}
	}
}

func (s *packetEndpoint) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.done)
		s.mu.Unlock()
		if s.notify != nil {
			s.link.RemoveNotify(s.notify)
		}
		<-s.outputDone
		s.active.Wait()
		s.link.Close()
		s.stack.RemoveNIC(1)
		s.stack.Close()
		s.stack.Wait()
		close(s.events)
	})
	return nil
}

func (s *packetEndpoint) listenAddress() tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(s.address.AsSlice()), Port: 53}
}

func (s *packetEndpoint) listenTCP() (*gonet.TCPListener, error) {
	if !s.begin() {
		return nil, os.ErrClosed
	}
	defer s.active.Done()
	return gonet.ListenTCP(s.stack, s.listenAddress(), s.protocol)
}

func (s *packetEndpoint) listenUDP() (*gonet.UDPConn, error) {
	if !s.begin() {
		return nil, os.ErrClosed
	}
	defer s.active.Done()
	address := s.listenAddress()
	return gonet.DialUDP(s.stack, &address, nil, s.protocol)
}
