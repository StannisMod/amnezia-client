package awg

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// The production recovery API must preserve the established TCP socket when
// reopening the protected UDP bind.
// This preserves the UDP port; it does NOT test NAT rebinding or interface moves.
func TestBindUpdatePreservesEstablishedTCP(t *testing.T) {
	for _, standard := range []bool{false, true} {
		for _, ipv6 := range []bool{false, true} {
			t.Run(fmt.Sprintf("standard=%t/ipv6=%t", standard, ipv6), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				clientIP, serverIP, mask := "10.77.0.1", "10.77.0.2", "/32"
				if ipv6 {
					clientIP, serverIP, mask = "fd77::1", "fd77::2", "/128"
				}
				aPriv, aPub := keypair(t)
				bPriv, bPub := keypair(t)
				reserved, e := net.ListenPacket("udp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				clientPort := uint16(reserved.LocalAddr().(*net.UDPAddr).Port)
				defer reserved.Close()
				params := map[string]string(nil)
				if !standard {
					params = map[string]string{"jc": "3", "jmin": "40", "jmax": "80", "s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}
				}
				var lc net.ListenConfig
				peer, e := New(ctx, Config{Address: []netip.Addr{netip.MustParseAddr(serverIP)}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), clientPort), AllowedIPs: []netip.Prefix{netip.MustParsePrefix(clientIP + mask)}, Parameters: params}, lc.ListenPacket)
				if e != nil {
					t.Fatal(e)
				}
				defer peer.Close()
				peerPort, e := peer.LocalPort()
				if e != nil {
					t.Fatal(e)
				}
				var opens atomic.Int32
				var claimed atomic.Bool
				client, e := New(ctx, Config{Address: []netip.Addr{netip.MustParseAddr(clientIP)}, PrivateKey: aPriv, PublicKey: bPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), peerPort), ListenPort: clientPort, AllowedIPs: []netip.Prefix{netip.MustParsePrefix(serverIP + mask)}, Parameters: params}, func(c context.Context, n, a string) (net.PacketConn, error) {
					var pc net.PacketConn
					var e error
					if claimed.CompareAndSwap(false, true) {
						pc = reserved
					} else {
						pc, e = lc.ListenPacket(c, n, a)
					}
					if e == nil {
						opens.Add(1)
					}
					return pc, e
				})
				if e != nil {
					t.Fatal(e)
				}
				defer client.Close()
				listener, e := peer.Net.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverIP), 8080))
				if e != nil {
					t.Fatal(e)
				}
				defer listener.Close()
				var accepts atomic.Int32
				go func() {
					for {
						c, e := listener.Accept()
						if e != nil {
							return
						}
						accepts.Add(1)
						go func() { defer c.Close(); io.Copy(c, c) }()
					}
				}()
				stream, e := client.DialContext(ctx, "tcp", net.JoinHostPort(serverIP, "8080"))
				if e != nil {
					t.Fatal(e)
				}
				defer stream.Close()
				stream.SetDeadline(time.Now().Add(10 * time.Second))
				for cycle := 0; cycle < 4; cycle++ {
					if cycle > 0 {
						if e := client.RefreshUnderlay(netip.AddrPort{}); e != nil {
							t.Fatal(e)
						}
					}
					payload := fmt.Sprintf("same TCP, UDP bind generation %d", cycle)
					if _, e := io.WriteString(stream, payload); e != nil {
						t.Fatal(e)
					}
					got := make([]byte, len(payload))
					if _, e := io.ReadFull(stream, got); e != nil {
						t.Fatal(e)
					}
					if string(got) != payload || accepts.Load() != 1 {
						t.Fatal("existing TCP did not survive bind update")
					}
				}
				if opens.Load() != 4 {
					t.Fatalf("expected 4 UDP socket generations, got %d", opens.Load())
				}
				t.Log("same TCP socket and one server accept survived 3 real UDP socket reopenings")
			})
		}
	}
}
