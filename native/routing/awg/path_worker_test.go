package awg

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestPathMTUWorkerClosesDuringUnansweredProbe(t *testing.T) {
	private, _ := keypair(t)
	_, public := keypair(t)
	c := Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: private, PublicKey: public, Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")}, PathMTUProbe: netip.MustParseAddr("10.77.0.2")}
	var lc net.ListenConfig
	transport, err := New(context.Background(), c, lc.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	tcpWorker := transport.tcpWorker
	if tcpWorker == nil {
		t.Fatal("configured TCP path worker was not started")
	}
	worker := transport.mtuWorker
	if worker == nil {
		t.Fatal("configured MTU worker was not started")
	}
	worker.invalidate()
	until := time.Now().Add(time.Second)
	started := false
	for time.Now().Before(until) {
		worker.mu.Lock()
		started = worker.checkCancel != nil
		worker.mu.Unlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !started {
		t.Fatal("measurement did not start")
	}
	done := make(chan error, 1)
	go func() { done <- transport.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close waited for probe deadline")
	}
	select {
	case <-worker.done:
	default:
		t.Fatal("MTU worker survived transport close")
	}
	select {
	case <-tcpWorker.done:
	default:
		t.Fatal("TCP path worker survived transport close")
	}
	if mtu, _ := transport.Net.MTU(); mtu != 1280 {
		t.Fatal("unanswered probe changed MTU", mtu)
	}
}

func TestPathMTUProbeMustStayInsidePeerScope(t *testing.T) {
	private, _ := keypair(t)
	_, public := keypair(t)
	base := Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: private, PublicKey: public, Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")}}
	for _, address := range []string{"10.77.0.1", "192.0.2.1", "127.0.0.1", "224.0.0.1", "::1", "0.0.0.0"} {
		c := base
		c.PathMTUProbe = netip.MustParseAddr(address)
		if err := c.Validate(); err == nil {
			t.Fatal("invalid probe address accepted", address)
		}
	}
	base.PathMTUProbe = netip.MustParseAddr("10.77.0.2")
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Repeated TCP timeouts during a complete outage must neither manufacture a
// lower MTU nor produce an unbounded stream of measurement packets.
func TestPathMTUWorkerTimeoutStormIsBoundedAndInconclusive(t *testing.T) {
	_, flow, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	var probes atomic.Int64
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		packet := make([]byte, 65535)
		sizes := make([]int, 1)
		for {
			if _, err := flow.Read([][]byte{packet}, sizes, 0); err != nil {
				return
			}
			probes.Add(1) // No reply: the entire peer path is unavailable.
		}
	}()
	worker := startPathMTUWorker(context.Background(), flow, netip.MustParseAddr("10.77.0.2"))
	defer worker.stop()
	until := time.Now().Add(7200 * time.Millisecond)
	for time.Now().Before(until) {
		flow.stack.Stats().TCP.Timeouts.Increment()
		time.Sleep(20 * time.Millisecond)
	}
	worker.stop()
	if count := probes.Load(); count < 3 || count > 6 {
		t.Fatalf("unbounded or absent loss-triggered probing: %d packets", count)
	}
	if mtu, _ := flow.MTU(); mtu != 1420 {
		t.Fatalf("total outage manufactured MTU evidence: %d", mtu)
	}
	flow.Close()
	select {
	case <-readerDone:
	case <-time.After(time.Second):
		t.Fatal("packet reader survived closed stack")
	}
}
