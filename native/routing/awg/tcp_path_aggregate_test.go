package awg

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// A global count of 32 timeouts does not imply four per socket: different
// initial RTTs and scheduling can leave some sockets near their next RTO.
// Observe the real endpoints without changing their timers. The lower bound
// on each timeout's time is the previous poll, so scheduler pauses make this
// check conservative rather than inventing extra recovery time.
func awaitAggregateRecoveryWindow(t *testing.T, ctx context.Context, baseline []uint64, baselineAt []time.Time, endpoints []tcpip.Endpoint) {
	t.Helper()
	lastCounts := append([]uint64(nil), baseline...)
	lastReads, earliest := append([]time.Time(nil), baselineAt...), make([]time.Time, len(endpoints))
	deadline := time.Now().Add(12 * time.Second)
	for {
		ready := true
		for i, ep := range endpoints {
			readAt := time.Now()
			var info tcpip.TCPInfoOption
			if err := ep.GetSockOpt(&info); err != nil {
				t.Fatal("TCP backoff snapshot", err)
			}
			count := ep.Stats().(*tcp.Stats).SendErrors.Timeouts.Value()
			if count != lastCounts[i] {
				earliest[i] = lastReads[i]
				lastCounts[i] = count
			}
			lastReads[i] = readAt
			if count < baseline[i]+4 || earliest[i].IsZero() || info.RTO-time.Since(earliest[i]) < 3*time.Second {
				ready = false
			}
		}
		if ready {
			return
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatalf("sockets did not reach a safe recovery window: baseline=%v observed=%v", baseline, lastCounts)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testEncryptedAggregateRecovery(t *testing.T, ctx context.Context, client *Transport, relay *recoveryRelay, first net.Conn, peer string, accepts *atomic.Int32, unevenRTO ...bool) {
	t.Helper()
	streams := []net.Conn{first}
	for len(streams) < 8 {
		var saved tcpip.TCPMinRTOOption
		uneven := len(unevenRTO) > 0 && unevenRTO[0] && len(streams) == 7
		if uneven {
			if err := client.Net.stack.TransportProtocolOption(tcp.ProtocolNumber, &saved); err != nil {
				t.Fatal(err)
			}
			slower := tcpip.TCPMinRTOOption(2 * time.Duration(saved))
			if err := client.Net.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &slower); err != nil {
				t.Fatal(err)
			}
		}
		stream, err := client.DialContext(ctx, "tcp", net.JoinHostPort(peer, "8080"))
		if uneven {
			if resetErr := client.Net.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &saved); resetErr != nil {
				t.Fatal(resetErr)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		stream.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err = stream.Write([]byte{99}); err != nil {
			t.Fatal(err)
		}
		var reply [1]byte
		if _, err = io.ReadFull(stream, reply[:]); err != nil || reply[0] != 99 {
			t.Fatal("warmup", err)
		}
		streams = append(streams, stream)
	}
	if accepts.Load() != 8 {
		t.Fatal("streams not established", accepts.Load())
	}
	original := client.Net
	endpoints := make([]tcpip.Endpoint, len(streams))
	baseline := make([]uint64, len(streams))
	baselineAt := make([]time.Time, len(streams))
	for i, stream := range streams {
		local, err := netip.ParseAddrPort(stream.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		remote, err := netip.ParseAddrPort(stream.RemoteAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		localAddress, protocol := flowAddress(local)
		remoteAddress, _ := flowAddress(remote)
		ep := original.stack.FindTransportEndpoint(protocol, tcp.ProtocolNumber, stack.TransportEndpointID{LocalAddress: localAddress.Addr, LocalPort: local.Port(), RemoteAddress: remoteAddress.Addr, RemotePort: remote.Port()}, 1)
		var ok bool
		endpoints[i], ok = ep.(tcpip.Endpoint)
		if !ok {
			t.Fatal("original TCP endpoint is missing")
		}
		baselineAt[i] = time.Now()
		baseline[i] = endpoints[i].Stats().(*tcp.Stats).SendErrors.Timeouts.Value()
	}
	relay.drop.Store(true)
	for i, stream := range streams {
		if _, err := stream.Write([]byte{byte(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	awaitAggregateRecoveryWindow(t, ctx, baseline, baselineAt, endpoints)
	time.Sleep(150 * time.Millisecond)
	backedOff := client.Net.stack.Stats().TCP.Timeouts.Value()
	retransmits := client.Net.stack.Stats().TCP.Retransmits.Value()
	returned := time.Now()
	relay.drop.Store(false)
	until := time.Now().Add(1200 * time.Millisecond)
	for client.Net.stack.Stats().TCP.Retransmits.Value() == retransmits {
		if time.Now().After(until) {
			t.Fatal("no automatic repair batch")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if delta := client.Net.stack.Stats().TCP.Retransmits.Value() - retransmits; delta > tcpProbePackets {
		t.Fatal("first repair batch exceeded peer budget", delta)
	}
	// A second proof arrives within this interval. It must not replenish the
	// aggregate packet allowance even though four other sockets are eligible.
	time.Sleep(700 * time.Millisecond)
	if delta := client.Net.stack.Stats().TCP.Retransmits.Value() - retransmits; delta > tcpProbePackets {
		t.Fatal("new proof replenished wire budget", delta)
	}
	for i, stream := range streams {
		stream.SetReadDeadline(returned.Add(2500 * time.Millisecond))
		var reply [1]byte
		if _, err := io.ReadFull(stream, reply[:]); err != nil || reply[0] != byte(i+1) {
			t.Fatal("socket starved or corrupted", i, err)
		}
	}
	if delta := client.Net.stack.Stats().TCP.Retransmits.Value() - retransmits; delta != uint64(len(streams)) {
		t.Fatal("unexpected repair count", delta)
	}
	if client.Net.stack.Stats().TCP.Timeouts.Value() != backedOff {
		t.Fatal("normal timeout concealed aggregate recovery")
	}
	if client.Net != original || accepts.Load() != 8 {
		t.Fatal("aggregate recovery recreated connections")
	}
	t.Logf("all eight original TCP sockets recovered in %s with four-packet peer budget", time.Since(returned))
}
