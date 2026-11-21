package awg

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestTCPWorkerDoesNotProbeWithoutRecoveringSocket(t *testing.T) {
	_, flow, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.80.0.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	worker := startTCPPathWorker(context.Background(), flow, netip.MustParseAddr("10.80.0.2"))
	defer worker.stop()
	// Even an aggregate timeout is insufficient without an actual owned socket
	// still waiting for payload retransmission.
	flow.stack.Stats().TCP.Timeouts.Increment()
	select {
	case packet := <-flow.packets:
		packet.Release()
		t.Fatal("idle worker generated probe traffic")
	case <-time.After(1100 * time.Millisecond):
	}
}
