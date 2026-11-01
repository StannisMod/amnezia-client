//go:build !android && !ios

package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// Pin the disposable multihomed peer's reply address. The stock sticky
// IP_PKTINFO bind can select the receiving interface's primary address for an
// endpoint IP owned by another interface. Production validation stays intact.
type fixedFixtureBind struct {
	mu      sync.Mutex
	address string
	pc      net.PacketConn
}

func (b *fixedFixtureBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	pc, err := net.ListenPacket("udp4", net.JoinHostPort(b.address, strconv.Itoa(int(port))))
	if err != nil {
		return nil, 0, err
	}
	b.pc = pc
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n, source, err := pc.ReadFrom(packets[0])
		if err != nil {
			return 0, err
		}
		address, err := netip.ParseAddrPort(source.String())
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		endpoints[0] = fixtureEndpoint(address)
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, uint16(pc.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *fixedFixtureBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc == nil {
		return nil
	}
	err := b.pc.Close()
	b.pc = nil
	return err
}

func (b *fixedFixtureBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	address, err := netip.ParseAddrPort(endpoint.DstToString())
	if err != nil {
		return err
	}
	for _, packet := range packets {
		if _, err := pc.WriteTo(packet, net.UDPAddrFromAddrPort(address)); err != nil {
			return err
		}
	}
	return nil
}

func (*fixedFixtureBind) BatchSize() int { return 1 }
func (*fixedFixtureBind) SetMark(mark uint32) error {
	if mark != 0 {
		return fmt.Errorf("disposable peer does not use routing marks")
	}
	return nil
}
func (*fixedFixtureBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(text)
	return fixtureEndpoint(address), err
}

type fixtureEndpoint netip.AddrPort

func (fixtureEndpoint) ClearSrc()             {}
func (fixtureEndpoint) SrcToString() string   { return "" }
func (fixtureEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }
func (e fixtureEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e fixtureEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e fixtureEndpoint) DstToBytes() []byte {
	result, _ := netip.AddrPort(e).MarshalBinary()
	return result
}
