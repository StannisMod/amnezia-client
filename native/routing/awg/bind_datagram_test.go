package awg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

type bindPacketWrapper struct {
	*net.UDPConn
	reads  atomic.Int32
	writes atomic.Int32
}

func (p *bindPacketWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	p.reads.Add(1)
	return p.UDPConn.ReadFrom(b)
}
func (p *bindPacketWrapper) WriteTo(b []byte, a net.Addr) (int, error) {
	p.writes.Add(1)
	return p.UDPConn.WriteTo(b, a)
}

func openDatagramBind(t testing.TB, network string, wrapped bool) (*packetBind, *net.UDPConn, conn.ReceiveFunc, netip.AddrPort) {
	t.Helper()
	host := "127.0.0.1"
	if network == "udp6" {
		host = "::1"
	}
	peer, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(host), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	var lc net.ListenConfig
	bind := &packetBind{ctx: context.Background(), endpoint: peer.LocalAddr().(*net.UDPAddr).AddrPort(), listen: func(ctx context.Context, n, a string) (net.PacketConn, error) {
		pc, err := lc.ListenPacket(ctx, n, a)
		if err == nil && wrapped {
			return &bindPacketWrapper{UDPConn: pc.(*net.UDPConn)}, nil
		}
		return pc, err
	}}
	receive, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bind.Close() })
	return bind, peer, receive[0], netip.AddrPortFrom(netip.MustParseAddr(host), port)
}

func TestPacketBindDatagramsKeepPeerFilterAndWrapper(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapped=%t", network, wrapped), func(t *testing.T) {
				bind, peer, receive, local := openDatagramBind(t, network, wrapped)
				if err := bind.pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				stranger, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(local.Addr(), 0)))
				if err != nil {
					t.Fatal(err)
				}
				defer stranger.Close()
				if _, err = stranger.WriteToUDPAddrPort([]byte("foreign"), local); err != nil {
					t.Fatal(err)
				}
				if _, err = peer.WriteToUDPAddrPort([]byte("expected"), local); err != nil {
					t.Fatal(err)
				}
				packets, sizes, endpoints := [][]byte{make([]byte, 128)}, make([]int, 1), make([]conn.Endpoint, 1)
				n, err := receive(packets, sizes, endpoints)
				if err != nil || n != 1 || string(packets[0][:sizes[0]]) != "expected" {
					t.Fatalf("peer filter: n=%d err=%v payload=%q", n, err, packets[0][:sizes[0]])
				}
				if err = bind.Send([][]byte{[]byte("response")}, endpoints[0]); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, 128)
				n, from, err := peer.ReadFromUDPAddrPort(reply)
				if err != nil || string(reply[:n]) != "response" || from != local {
					t.Fatalf("response: %q from=%v err=%v", reply[:n], from, err)
				}
				if wrapped {
					wrapper := bind.pc.(*bindPacketWrapper)
					if wrapper.reads.Load() < 2 || wrapper.writes.Load() != 1 {
						t.Fatal("UDP fast path bypassed wrapper methods")
					}
				}
			})
		}
	}
}

func BenchmarkPacketBindDatagrams(b *testing.B) {
	for _, wrapped := range []bool{false, true} {
		b.Run(fmt.Sprintf("wrapped=%t", wrapped), func(b *testing.B) {
			bind, peer, receive, local := openDatagramBind(b, "udp4", wrapped)
			payload := make([]byte, 64)
			packets, sizes, endpoints := [][]byte{make([]byte, 128)}, make([]int, 1), make([]conn.Endpoint, 1)
			b.ReportAllocs()
			b.SetBytes(128)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := peer.WriteToUDPAddrPort(payload, local); err != nil {
					b.Fatal(err)
				}
				if _, err := receive(packets, sizes, endpoints); err != nil {
					b.Fatal(err)
				}
				if err := bind.Send([][]byte{payload}, endpoints[0]); err != nil {
					b.Fatal(err)
				}
				if _, _, err := peer.ReadFromUDPAddrPort(packets[0]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
