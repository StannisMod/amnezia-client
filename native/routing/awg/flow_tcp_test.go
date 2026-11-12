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

func TestTCPCloseWithPausedDeviceReader(t *testing.T) {
	_, a, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, b, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var pause atomic.Bool
	paused, resume := make(chan struct{}, 1), make(chan struct{})
	defer close(resume)
	pump := func(from, to *FlowStack, canPause bool) {
		packet, sizes := make([]byte, 65535), make([]int, 1)
		for {
			if _, err := from.Read([][]byte{packet}, sizes, 0); err != nil {
				return
			}
			if canPause && pause.Load() {
				select {
				case paused <- struct{}{}:
				default:
				}
				select {
				case <-resume:
				case <-from.done:
					return
				}
			}
			if _, err := to.Write([][]byte{packet[:sizes[0]]}, 0); err != nil {
				return
			}
		}
	}
	go pump(a, b, true)
	go pump(b, a, false)
	listener, err := b.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.2:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := listener.Accept(); err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := a.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var server net.Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Close the stacks before cleaning up sockets even when an assertion fails.
	t.Cleanup(func() { a.Close(); b.Close(); client.Close(); server.Close() })
	pause.Store(true)
	udp, err := a.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go udp.WriteTo([]byte("pause-reader"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.77.0.2:9")))
	select {
	case <-paused:
	case <-ctx.Done():
		t.Fatal("device reader did not pause")
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP Close held endpoint locks waiting for the paused device reader")
	}
	if len(a.tcpConnectionsSnapshot()) != 0 {
		t.Fatal("closed TCP still registered")
	}
}

func TestTCPRegistryPreservesHalfCloseAndOwnership(t *testing.T) {
	device, flow, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	listener, err := flow.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, e := listener.Accept()
		if e == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := flow.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server net.Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal("local TCP not accepted")
	}
	defer server.Close()
	server.SetDeadline(time.Now().Add(time.Second))
	client.SetDeadline(time.Now().Add(time.Second))
	tracked := client.(*flowTCPConn)
	snapshot := flow.tcpConnectionsSnapshot()
	if len(snapshot) != 1 || snapshot[0] != tracked.TCPConn {
		t.Fatal("registry lost actual TCP endpoint")
	}
	// A live, healthy TCP stream must not be retransmitted merely because a
	// path was verified. Exercise the dispatcher against the actual endpoint.
	proof := tcpPathProof{owner: flow, generation: flow.tcpPathGeneration, serial: 1, size: 1280, verifiedAt: time.Now()}
	flow.tcpProofSerial = 1
	if n := flow.dispatchTCPPathProof(proof); n != 0 {
		t.Fatal("healthy stream probed", n)
	}
	if flow.tcpProbeBudget.attempts != 1 || flow.tcpProbeBudget.packets != 0 {
		t.Fatal("dispatcher accounting")
	}
	flow.invalidateTCPPath()
	if n := flow.dispatchTCPPathProof(proof); n != 0 || flow.tcpProbeBudget.attempts != 1 {
		t.Fatal("stale proof reached endpoint")
	}
	if err = client.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err = server.Read(one[:]); err != io.EOF {
		t.Fatal("half-close lost FIN", err)
	}
	if len(flow.tcpConnectionsSnapshot()) != 1 {
		t.Fatal("half-close removed a live reading endpoint")
	}
	if _, err = server.Write([]byte{71}); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(client, one[:]); err != nil || one[0] != 71 {
		t.Fatal("half-close broke reverse traffic", err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if len(flow.tcpConnectionsSnapshot()) != 0 {
		t.Fatal("closed TCP endpoint retained")
	}
	go func() {
		conn, e := listener.Accept()
		if e == nil {
			accepted <- conn
		}
	}()
	second, err := flow.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	select {
	case peer := <-accepted:
		defer peer.Close()
	case <-ctx.Done():
		t.Fatal("second TCP not accepted")
	}
	if len(flow.tcpConnectionsSnapshot()) != 1 {
		t.Fatal("second active TCP endpoint not tracked")
	}
	device.Close()
	if len(flow.tcpConnectionsSnapshot()) != 0 {
		t.Fatal("closed flow retained endpoints")
	}
}
