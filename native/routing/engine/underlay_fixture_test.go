package engine

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

// Keep the client's fixed endpoint owned until its transport takes the socket.
// Closing a reservation before constructing the peer lets that peer (or DNS)
// acquire the same ephemeral port and makes the client fail during startup.
func reserveTestUnderlay(t *testing.T) (uint16, func(context.Context, string, string) (net.PacketConn, error)) {
	t.Helper()
	reserved, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reserved.Close() })
	port := uint16(reserved.LocalAddr().(*net.UDPAddr).Port)
	var claimed atomic.Bool
	var lc net.ListenConfig
	return port, func(ctx context.Context, network, address string) (net.PacketConn, error) {
		local, err := netip.ParseAddrPort(address)
		if network == "udp4" && err == nil && local.Port() == port && claimed.CompareAndSwap(false, true) {
			return reserved, nil
		}
		return lc.ListenPacket(ctx, network, address)
	}
}
