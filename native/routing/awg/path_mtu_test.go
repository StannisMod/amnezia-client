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
	var dropped, received atomic.Int64
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
	t.Logf("same TCP transferred complete payload after client MTU reduction in %s; original oversized packets dropped=%d", time.Since(repairStarted), dropped.Load())
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
