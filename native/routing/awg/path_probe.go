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
	if _, bounded := ctx.Deadline(); !bounded {
		return errors.New("MTU probe requires a deadline")
	}
	destination = destination.Unmap()
	if !destination.Is4() || destination.IsUnspecified() || destination.IsMulticast() || size < 60 || size > s.maximumMTU {
		return errors.New("invalid IPv4 MTU probe")
	}
	if !s.begin() {
		return net.ErrClosed
	}
	defer s.active.Done()
	var queue waiter.Queue
	ep, err := s.stack.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &queue)
	if err != nil {
		return errors.New(err.String())
	}
	defer ep.Close()
	if err := ep.Connect(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(destination.AsSlice())}); err != nil {
		return errors.New(err.String())
	}
	local, err := ep.GetLocalAddress()
	if err != nil || local.Addr.Len() != 4 {
		return errors.New("MTU probe has no IPv4 source")
	}
	packet := make([]byte, size)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], uint16(size))
	binary.BigEndian.PutUint16(packet[6:], 0x4000)
	packet[8] = 64
	packet[9] = 1
	copy(packet[12:16], local.Addr.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	echo := packet[20:]
	echo[0] = 8
	binary.BigEndian.PutUint16(echo[4:], local.Port)
	if _, err := rand.Read(echo[6:]); err != nil {
		return err
	}
	binary.BigEndian.PutUint16(echo[2:], probeChecksum(echo))
	binary.BigEndian.PutUint16(packet[10:], probeChecksum(packet[:20]))
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
			if len(reply) == len(echo) && reply[0] == 0 && reply[1] == 0 && bytes.Equal(reply[4:], echo[4:]) {
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
