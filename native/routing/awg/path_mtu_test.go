package awg

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlowPathMTULimits(t *testing.T) {
	for _, address := range []string{"10.77.0.1", "fd77::1"} {
		_, s, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr(address)}, 1420)
		if err != nil {
			t.Fatal(err)
		}
		minimum := 576
		if address == "fd77::1" {
			minimum = 1280
		}
		for _, mtu := range []int{minimum - 1, 1421} {
			if err := s.SetPathMTU(mtu); err == nil {
				t.Fatal("invalid MTU accepted", address, mtu)
			}
		}
		if err := s.SetPathMTU(minimum); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.MTU(); got != minimum || s.link.MTU() != uint32(minimum) {
			t.Fatal("link MTU not updated", got)
		}
		s.Close()
		if err := s.SetPathMTU(1420); err != net.ErrClosed {
			t.Fatal("closed stack accepted update", err)
		}
	}
}

func TestOldTCPAfterClientLinkMTUReduction(t *testing.T) {
	_, a, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, b, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var filter atomic.Bool
	var dropped atomic.Int64
	pump := func(from, to *FlowStack, filterOutput bool) {
		data := make([]byte, 65535)
		sizes := make([]int, 1)
		for {
			_, err := from.Read([][]byte{data}, sizes, 0)
			if err != nil {
				return
			}
			if filterOutput && filter.Load() && sizes[0] > 1200 {
				dropped.Add(1)
				continue
			}
			if _, err := to.Write([][]byte{data[:sizes[0]]}, 0); err != nil {
				return
			}
		}
	}
	go pump(a, b, true)
	go pump(b, a, false)
	testRetainedUploadMTU(t, a, b, &filter, &dropped)
}

func testRetainedUploadMTU(t *testing.T, a, b *FlowStack, filter *atomic.Bool, dropped *atomic.Int64) {
	t.Helper()
	var received atomic.Int64
	var corrupted atomic.Bool
	listener, err := b.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.2:18081"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := a.DialContext(ctx, "tcp", "10.77.0.2:18081")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server net.Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := server.Read(buf)
			base := received.Load()
			for i, value := range buf[:n] {
				want := byte(0)
				if base+int64(i) < 6 {
					want = "before"[base+int64(i)]
				}
				if value != want {
					corrupted.Store(true)
				}
			}
			received.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	client.Write([]byte("before"))
	until := time.Now().Add(time.Second)
	for received.Load() < 6 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if received.Load() != 6 {
		t.Fatal("initial flow did not transfer")
	}
	filter.Store(true)
	go io.CopyN(client, zeroReader{}, 256*1024)
	until = time.Now().Add(time.Second)
	for dropped.Load() == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if dropped.Load() == 0 {
		t.Fatal("large upload loss not reproduced")
	}
	time.Sleep(300 * time.Millisecond)
	if received.Load() != 6 {
		t.Fatalf("upload was not stalled before regulation: received=%d", received.Load())
	}
	repairStarted := time.Now()
	if err := a.SetPathMTU(1104); err != nil {
		t.Fatal(err)
	}
	until = time.Now().Add(8 * time.Second)
	for received.Load() < 256*1024+6 && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if received.Load() != 256*1024+6 {
		t.Fatalf("old TCP remained stalled after link MTU reduction: received=%d dropped=%d", received.Load(), dropped.Load())
	}
	if corrupted.Load() {
		t.Fatal("retained upload payload corrupted")
	}
	t.Logf("same TCP transferred complete payload after client MTU reduction in %s; original oversized packets dropped=%d", time.Since(repairStarted), dropped.Load())
}

type mtuLossConn struct {
	net.PacketConn
	filter  *atomic.Bool
	dropped *atomic.Int64
}

func (c *mtuLossConn) WriteTo(p []byte, to net.Addr) (int, error) {
	if c.filter.Load() && len(p) > 1200 {
		c.dropped.Add(1)
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, to)
}

func TestEncryptedAWGRetainedUploadMTU(t *testing.T) {
	for _, obfuscated := range []bool{false, true} {
		name := "plain"
		if obfuscated {
			name = "AWG31"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			aPriv, aPub := keypair(t)
			bPriv, bPub := keypair(t)
			var filter atomic.Bool
			var dropped atomic.Int64
			var lc net.ListenConfig
			params := map[string]string(nil)
			if obfuscated {
				params = map[string]string{"s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}
			}
			serverConfig := Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.2")}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")}, MTU: 1420, Parameters: params}
			b, err := New(ctx, serverConfig, lc.ListenPacket)
			if err != nil {
				t.Fatal(err)
			}
			serverPort, err := b.LocalPort()
			if err != nil {
				b.Close()
				t.Fatal(err)
			}
			a, err := New(ctx, Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: aPriv, PublicKey: bPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), serverPort), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")}, MTU: 1420, Parameters: params}, func(ctx context.Context, n, address string) (net.PacketConn, error) {
				pc, err := lc.ListenPacket(ctx, n, address)
				if err != nil {
					return nil, err
				}
				return &mtuLossConn{PacketConn: pc, filter: &filter, dropped: &dropped}, nil
			})
			if err != nil {
				b.Close()
				t.Fatal(err)
			}
			defer a.Close()
			clientPort, err := a.LocalPort()
			if err != nil {
				b.Close()
				t.Fatal(err)
			}
			b.Close()
			serverConfig.ListenPort = serverPort
			serverConfig.Endpoint = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), clientPort)
			b, err = New(ctx, serverConfig, lc.ListenPacket)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			testRetainedUploadMTU(t, a.Net, b.Net, &filter, &dropped)
		})
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
