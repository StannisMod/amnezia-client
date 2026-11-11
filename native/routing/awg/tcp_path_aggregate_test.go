package awg

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func testEncryptedAggregateRecovery(t *testing.T, ctx context.Context, client *Transport, relay *recoveryRelay, first net.Conn, peer string, accepts *atomic.Int32) {
	t.Helper()
	streams := []net.Conn{first}
	for len(streams) < 8 {
		stream, err := client.DialContext(ctx, "tcp", net.JoinHostPort(peer, "8080"))
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
	relay.drop.Store(true)
	beforeTimeouts := client.Net.stack.Stats().TCP.Timeouts.Value()
	for i, stream := range streams {
		if _, err := stream.Write([]byte{byte(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	until := time.Now().Add(8 * time.Second)
	for client.Net.stack.Stats().TCP.Timeouts.Value() < beforeTimeouts+4*uint64(len(streams)) {
		if time.Now().After(until) {
			t.Fatal("streams did not reach fourth timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	backedOff := client.Net.stack.Stats().TCP.Timeouts.Value()
	retransmits := client.Net.stack.Stats().TCP.Retransmits.Value()
	returned := time.Now()
	relay.drop.Store(false)
	until = time.Now().Add(1200 * time.Millisecond)
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
