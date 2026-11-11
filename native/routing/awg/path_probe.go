package awg

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func probeChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ProbeIPv4Path measures an exact inner IPv4 packet through the existing
// encrypted peer. DF prevents fragmentation from turning an oversized probe
// into a false success. It bypasses the current lowered link MTU only for this
// bounded probe, allowing the controller to test recovery up to the profile
// ceiling. Ordinary application traffic still uses the current link MTU.
func (s *FlowStack) ProbeIPv4Path(ctx context.Context, destination netip.Addr, size int) error {
	if !destination.Unmap().Is4() {
		return errors.New("IPv4 probe requires IPv4 peer")
	}
	return s.ProbePath(ctx, destination, size)
}

// ProbePath sends an unfragmented IPv4 or IPv6 echo of the exact inner size.
func (s *FlowStack) ProbePath(ctx context.Context, destination netip.Addr, size int) error {
	if _, bounded := ctx.Deadline(); !bounded {
		return errors.New("MTU probe requires a deadline")
	}
	destination = destination.Unmap()
	if !destination.IsValid() || destination.Zone() != "" || destination.IsUnspecified() || destination.IsMulticast() || size < 60 || (destination.Is6() && size < 80) || size > s.maximumMTU {
		return errors.New("invalid IP MTU probe")
	}
	if !s.begin() {
		return net.ErrClosed
	}
	defer s.active.Done()
	var queue waiter.Queue
	network, transport, ipHeader, replyType := ipv4.ProtocolNumber, icmp.ProtocolNumber4, 20, byte(0)
	if destination.Is6() {
		network, transport, ipHeader, replyType = ipv6.ProtocolNumber, icmp.ProtocolNumber6, 40, 129
	}
	ep, err := s.stack.NewEndpoint(transport, network, &queue)
	if err != nil {
		return errors.New(err.String())
	}
	defer ep.Close()
	if err := ep.Connect(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(destination.AsSlice())}); err != nil {
		return errors.New(err.String())
	}
	local, err := ep.GetLocalAddress()
	if err != nil || local.Addr.Len() != destination.BitLen()/8 {
		return errors.New("MTU probe has no source in the target family")
	}
	packet := make([]byte, size)
	if destination.Is4() {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:], uint16(size))
		binary.BigEndian.PutUint16(packet[6:], 0x4000)
		packet[8] = 64
		packet[9] = 1
		copy(packet[12:16], local.Addr.AsSlice())
		copy(packet[16:20], destination.AsSlice())
	} else {
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:], uint16(size-40))
		packet[6] = 58
		packet[7] = 64
		copy(packet[8:24], local.Addr.AsSlice())
		copy(packet[24:40], destination.AsSlice())
	}
	echo := packet[ipHeader:]
	echo[0] = 8
	if destination.Is6() {
		echo[0] = 128
	}
	binary.BigEndian.PutUint16(echo[4:], local.Port)
	if _, err := rand.Read(echo[6:]); err != nil {
		return err
	}
	if destination.Is4() {
		binary.BigEndian.PutUint16(echo[2:], probeChecksum(echo))
		binary.BigEndian.PutUint16(packet[10:], probeChecksum(packet[:20]))
	} else {
		pseudo := make([]byte, 40+len(echo))
		copy(pseudo[:16], local.Addr.AsSlice())
		copy(pseudo[16:32], destination.AsSlice())
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(echo)))
		pseudo[39] = 58
		copy(pseudo[40:], echo)
		binary.BigEndian.PutUint16(echo[2:], probeChecksum(pseudo))
	}
	view := buffer.NewViewWithData(packet)
	select {
	case s.packets <- view:
	case <-ctx.Done():
		view.Release()
		return ctx.Err()
	case <-s.done:
		view.Release()
		return net.ErrClosed
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var response bytes.Buffer
		if _, err := ep.Read(&response, tcpip.ReadOptions{}); err == nil {
			reply := response.Bytes()
			if len(reply) == len(echo) && reply[0] == replyType && reply[1] == 0 && bytes.Equal(reply[4:], echo[4:]) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return net.ErrClosed
		case <-ticker.C:
		}
	}
}
