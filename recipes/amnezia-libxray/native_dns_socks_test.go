package socks5

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/amnezia-vpn/amnezia-tun2socks/v2/metadata"
)

func TestNativeDNSHandshakeCancellation(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				c, err := listener.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				// Never answer the greeting. Cancellation must close the
				// actual native SOCKS handshake, not abandon a goroutine.
				_, _ = io.Copy(io.Discard, c)
			}()
			proxy, err := New(listener.Addr().String(), "", "")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			if transport == "tcp" {
				c, err := proxy.DialContext(ctx, &M.Metadata{Network: M.TCP,
					DstIP: netip.MustParseAddr("192.0.2.53"), DstPort: 53})
				if c != nil {
					c.Close()
				}
				if err == nil {
					t.Fatal("unanswered TCP handshake succeeded")
				}
			} else {
				c, err := proxy.DialUDPContext(ctx)
				if c != nil {
					c.Close()
				}
				if err == nil {
					t.Fatal("unanswered UDP associate succeeded")
				}
			}
			if time.Since(start) > time.Second {
				t.Fatal("native handshake ignored cancellation")
			}
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("native handshake socket remained owned")
			}
		})
	}
}
