package awg

import (
	"context"
	"net"
	"net/netip"
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
