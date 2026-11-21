package awg

import (
	"context"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestDualStackIPv4MTUCanRecoverBelowIPv6Minimum(t *testing.T) {
	_, a, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("fd77::1")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, b, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("fd77::2")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var largestIPv6TCP atomic.Int64
	var filtered atomic.Bool
	filtered.Store(true)
	pump := func(from, to *FlowStack, limit bool) {
		data := make([]byte, 65535)
		sizes := make([]int, 1)
		for {
			if _, err := from.Read([][]byte{data}, sizes, 0); err != nil {
				return
			}
			if limit && data[0]>>4 == 6 && data[6] == 6 {
				size := int64(sizes[0])
				for old := largestIPv6TCP.Load(); size > old; old = largestIPv6TCP.Load() {
					if largestIPv6TCP.CompareAndSwap(old, size) {
						break
					}
				}
			}
			threshold := 1200
			if data[0]>>4 == 6 {
				threshold = 1320
			}
			if limit && filtered.Load() && sizes[0] > threshold {
				continue
			}
			if _, err := to.Write([][]byte{data[:sizes[0]]}, 0); err != nil {
				return
			}
		}
	}
	go pump(a, b, true)
	go pump(b, a, false)
	controller, err := NewPathMTUController(a, netip.MustParseAddr("10.77.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	result, err := controller.Check(ctx)
	if err != nil || result.State != "reduced" || result.After > 1200 || result.After < 576 {
		t.Fatalf("IPv6 configuration prevented IPv4 adaptation: %+v %v", result, err)
	}
	ipv4MTU := result.After
	// Restore the modelled packet path without changing either private IP MTU.
	// IPv6 must still use its original ceiling, not an illegal sub-1280 link.
	filtered.Store(false)
	six, err := NewPathMTUController(a, netip.MustParseAddr("fd77::2"))
	if err != nil {
		t.Fatal(err)
	}
	result, err = six.Check(ctx)
	if err != nil || result.State != "unchanged" || result.Before != 1420 || result.After != 1420 {
		t.Fatalf("IPv4 adaptation changed IPv6: %+v %v", result, err)
	}
	fourProtocol := a.stack.NetworkProtocolInstance(ipv4.ProtocolNumber)
	sixProtocol := a.stack.NetworkProtocolInstance(ipv6.ProtocolNumber)
	if _, ok := fourProtocol.(stack.RejectIPv4WithHandler); !ok {
		t.Fatal("IPv4 rejection interface lost")
	}
	if _, ok := sixProtocol.(stack.RejectIPv6WithHandler); !ok {
		t.Fatal("IPv6 rejection interface lost")
	}
	if _, ok := fourProtocol.(stack.MulticastForwardingNetworkProtocol); !ok {
		t.Fatal("IPv4 forwarding interface lost")
	}
	if _, ok := sixProtocol.(stack.MulticastForwardingNetworkProtocol); !ok {
		t.Fatal("IPv6 forwarding interface lost")
	}
	listener, err := b.ListenTCPAddrPort(netip.MustParseAddrPort("[fd77::2]:18111"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- err
			return
		}
		defer conn.Close()
		_, err = io.CopyN(io.Discard, conn, 32768)
		received <- err
	}()
	client, err := a.DialContext(ctx, "tcp", "[fd77::2]:18111")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	largestIPv6TCP.Store(0)
	if _, err := client.Write(make([]byte, 32768)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if size := largestIPv6TCP.Load(); size <= 1280 || size > 1420 {
		t.Fatalf("IPv6 TCP did not retain its independent MTU: %d", size)
	}
	proof, err := a.verifyTCPPath(ctx, netip.MustParseAddr("10.77.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	if proof.size != ipv4MTU || !a.validTCPPathProof(proof, time.Now()) {
		t.Fatal("IPv4 proof lost its measured packet size")
	}
	if a.tcpPathProofFitsConnection(proof, client.(*flowTCPConn)) {
		t.Fatal("small IPv4 proof authorized larger IPv6 TCP packets")
	}
	if err := a.setFamilyPathMTU(netip.MustParseAddr("fd77::2"), 1280); err != nil {
		t.Fatal(err)
	}
	if a.validTCPPathProof(proof, time.Now()) {
		t.Fatal("other-family MTU change retained stale TCP proof")
	}
	if a.pathMTU(netip.MustParseAddr("10.77.0.2")) != ipv4MTU {
		t.Fatal("IPv6 update changed IPv4 MTU")
	}
	if err := a.setFamilyPathMTU(netip.MustParseAddr("fd77::2"), 1279); err == nil {
		t.Fatal("IPv6 minimum weakened")
	}
	if err := a.setFamilyPathMTU(netip.MustParseAddr("10.77.0.2"), 575); err == nil {
		t.Fatal("IPv4 minimum weakened")
	}
	if err := a.SetPathMTU(1104); err == nil {
		t.Fatal("global update disabled IPv6 minimum")
	}

	// The production worker must measure both configured families, rather than
	// leaving IPv6 at the original ceiling after the preferred IPv4 check.
	if err := a.SetPathMTU(1420); err != nil {
		t.Fatal(err)
	}
	filtered.Store(true)
	worker := startPathMTUWorker(context.Background(), a, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("fd77::2"))
	defer worker.stop()
	worker.invalidate()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		four := a.pathMTU(netip.MustParseAddr("10.77.0.2"))
		six := a.pathMTU(netip.MustParseAddr("fd77::2"))
		if four <= 1200 && six >= 1280 && six <= 1320 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("worker failed to measure both families: IPv4=%d IPv6=%d", a.pathMTU(netip.MustParseAddr("10.77.0.2")), a.pathMTU(netip.MustParseAddr("fd77::2")))

}
