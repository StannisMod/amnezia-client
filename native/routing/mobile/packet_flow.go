//go:build with_gvisor

package mobile

import (
	"errors"
	"net"
	"sync"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-tun"
)

// PacketFlow adapts public packet APIs such as NEPacketTunnelFlow to the same
// gVisor stack as Android. No private utun descriptor or second reader is used.
// The writer must copy the packet before returning and must not call Close.
type PacketFlow struct {
	mu       sync.RWMutex
	closed   bool
	endpoint *channel.Endpoint
	notify   *channel.NotificationHandle
	writer   func([]byte) error
}

var _ tun.GVisorTun = (*PacketFlow)(nil)

func NewPacketFlow(mtu uint32, writer func([]byte) error) (*PacketFlow, error) {
	if mtu < 1280 || mtu > 65535 || writer == nil {
		return nil, errors.New("invalid packet-flow host")
	}
	p := &PacketFlow{endpoint: channel.New(1024, mtu, ""), writer: writer}
	p.notify = p.endpoint.AddNotify(p)
	return p, nil
}

func (p *PacketFlow) Name() (string, error)                { return "amnezia-packet-flow", nil }
func (p *PacketFlow) Start() error                         { return nil }
func (p *PacketFlow) UpdateRouteOptions(tun.Options) error { return unsupported }
func (p *PacketFlow) Read([]byte) (int, error)             { return 0, unsupported }
func (p *PacketFlow) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, stack.NICOptions{}, net.ErrClosed
	}
	return p.endpoint, stack.NICOptions{}, nil
}

// Feed copies input because the native packet buffer belongs to the caller.
func (p *PacketFlow) Feed(packet []byte) error {
	if len(packet) == 0 || len(packet) > 65535 {
		return errors.New("invalid IP packet")
	}
	var protocol tcpip.NetworkProtocolNumber
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < header.IPv4MinimumSize {
			return errors.New("truncated IPv4 packet")
		}
		protocol = header.IPv4ProtocolNumber
	case 6:
		if len(packet) < header.IPv6MinimumSize {
			return errors.New("truncated IPv6 packet")
		}
		protocol = header.IPv6ProtocolNumber
	default:
		return errors.New("invalid IP version")
	}
	p.mu.RLock()
	closed := p.closed
	p.mu.RUnlock()
	if closed {
		return net.ErrClosed
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), packet...))})
	defer pkt.DecRef()
	// Injection may synchronously produce output; do not hold mu while calling it.
	p.endpoint.InjectInbound(protocol, pkt)
	return nil
}

func (p *PacketFlow) Write(packet []byte) (int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return 0, net.ErrClosed
	}
	if err := p.writer(packet); err != nil {
		return 0, err
	}
	return len(packet), nil
}

func (p *PacketFlow) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	packet := make([]byte, 0, pkt.Size())
	for _, part := range pkt.AsSlices() {
		packet = append(packet, part...)
	}
	return p.Write(packet)
}

func (p *PacketFlow) WriteNotify() {
	for {
		pkt := p.endpoint.Read()
		if pkt == nil {
			return
		}
		p.WritePacket(pkt)
		pkt.DecRef()
	}
}

func (p *PacketFlow) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	// All synchronous native writes have returned before Close returns.
	p.endpoint.RemoveNotify(p.notify)
	p.endpoint.Attach(nil)
	p.endpoint.Close()
	return nil
}
