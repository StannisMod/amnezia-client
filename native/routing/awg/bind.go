package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// ListenUnderlay must protect/bind the socket before it can send a datagram.
// A missing callback is an error, never an implicit unprotected fallback.
type ListenUnderlay func(context.Context, string, string) (net.PacketConn, error)

type packetBind struct {
	mu       sync.Mutex
	ctx      context.Context
	listen   ListenUnderlay
	endpoint netip.AddrPort
	pc       net.PacketConn
}

var _ conn.Bind = (*packetBind)(nil)

func (b *packetBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	network, address := "udp4", "0.0.0.0"
	if b.endpoint.Addr().Is6() {
		network, address = "udp6", "::"
	}
	pc, err := b.listen(b.ctx, network, net.JoinHostPort(address, strconv.Itoa(int(port))))
	if err != nil {
		return nil, 0, err
	}
	local, err := netip.ParseAddrPort(pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return nil, 0, errors.New("underlay returned an invalid UDP local address")
	}
	b.pc = pc
	// Capture this generation, so reopening never makes an old reader consume
	// datagrams from the new socket.
	receive := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, from, e := pc.ReadFrom(packets[0])
			if e != nil {
				return 0, e
			}
			addr, e := netip.ParseAddrPort(from.String())
			if e != nil {
				continue
			}
			addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
			if addr != b.endpoint {
				continue
			}
			sizes[0] = n
			eps[0] = endpoint(addr)
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{receive}, local.Port(), nil
}

func (b *packetBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc == nil {
		return nil
	}
	err := b.pc.Close()
	b.pc = nil
	return err
}
func (b *packetBind) SetMark(mark uint32) error {
	// Marking belongs in ListenUnderlay, before socket use.
	if mark != 0 {
		return errors.New("configure routing marks in the native underlay socket factory")
	}
	return nil
}
func (b *packetBind) BatchSize() int { return 1 }
func (b *packetBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	if ep.DstToString() != b.endpoint.String() {
		return conn.ErrWrongEndpointType
	}
	for _, p := range bufs {
		if _, err := pc.WriteTo(p, net.UDPAddrFromAddrPort(b.endpoint)); err != nil {
			return err
		}
	}
	return nil
}
func (b *packetBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, e := netip.ParseAddrPort(s)
	return endpoint(a), e
}

type endpoint netip.AddrPort

func (e endpoint) ClearSrc()           {}
func (e endpoint) SrcToString() string { return "" }
func (e endpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e endpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e endpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}
