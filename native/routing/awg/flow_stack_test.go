package awg

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Closing must unblock a notifier whose packet is waiting for the AWG reader,
// and must also be safe when TCP/UDP producers are still active.
func TestFlowStackCloseDuringPendingOutput(t *testing.T) {
	for i := 0; i < 10; i++ {
		device, flow, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, 1280)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := flow.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:0"))
		if err != nil {
			device.Close()
			t.Fatal(err)
		}
		sending, finished := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(finished)
			close(sending)
			for j := 0; j < 100; j++ {
				if _, err := conn.WriteTo([]byte("pending"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.77.0.2:9"))); err != nil {
					return
				}
			}
		}()
		<-sending
		closed := make(chan struct{})
		go func() { device.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("flow shutdown blocked on an unread output packet")
		}
		conn.Close()
		device.Close()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Fatal("flow producer survived shutdown")
		}
	}
}

func TestFlowStackCloseCancelsPendingDial(t *testing.T) {
	device, flow, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	dialDone := make(chan error, 1)
	go func() {
		conn, err := flow.DialContext(context.Background(), "tcp", "10.77.0.2:80")
		if conn != nil {
			conn.Close()
		}
		dialDone <- err
	}()
	packetRead := make(chan error, 1)
	go func() { _, err := device.Read([][]byte{make([]byte, 65535)}, make([]int, 1), 0); packetRead <- err }()
	select {
	case err = <-packetRead:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending TCP dial did not emit SYN")
	}
	device.Close()
	select {
	case err = <-dialDone:
		if err == nil {
			t.Fatal("closed flow stack completed a TCP dial")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not cancel the TCP dial")
	}
}
