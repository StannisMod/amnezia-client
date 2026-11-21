package awg

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// gVisor invokes its link notifier inside transport sends, including TCP
// Close. Waiting for the encrypted device reader there can hold endpoint locks
// indefinitely while the underlay is paused or shutting down.
func TestFlowOutputDoesNotWaitForDeviceReader(t *testing.T) {
	device, flow, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	conn, err := flow.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	written := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("queued-before-reader"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.77.0.2:9")))
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("transport send waited for the device reader")
	}
	read := make(chan error, 1)
	go func() {
		packet, sizes := make([]byte, 65535), make([]int, 1)
		_, err := device.Read([][]byte{packet}, sizes, 0)
		if err == nil && (sizes[0] < len("queued-before-reader") || string(packet[sizes[0]-len("queued-before-reader"):sizes[0]]) != "queued-before-reader") {
			err = net.ErrClosed
		}
		read <- err
	}()
	select {
	case err := <-read:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued packet was not delivered when the reader returned")
	}
}

func TestFlowOutputQueueBoundedAndDrained(t *testing.T) {
	device, flow, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	conn, err := flow.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for i := 0; i < 2048; i++ {
			// Overflow is allowed to drop packets, as on the bounded gVisor
			// link; it must not block transports or allocate an unbounded queue.
			conn.WriteTo([]byte("saturate"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.77.0.2:9")))
		}
	}()
	select {
	case <-sent:
	case <-time.After(3 * time.Second):
		t.Fatal("full output queue blocked sender")
	}
	if n := flow.endpoint.NumQueued(); n == 0 || n > 1024 {
		t.Fatalf("unexpected bounded queue size: %d", n)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if n := flow.endpoint.NumQueued(); n != 0 {
		t.Fatalf("closed output queue retained %d packets", n)
	}
	select {
	case <-flow.outputDone:
	default:
		t.Fatal("output worker survived Close")
	}
}

// Closing must unblock the output worker waiting for the AWG reader,
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
