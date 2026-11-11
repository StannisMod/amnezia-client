package awg

import (
	"testing"
	"time"
)

func TestTCPProbeBudgetBoundsAttemptsAndPackets(t *testing.T) {
	now := time.Now()
	var work tcpProbeBudget
	for i := 0; i < tcpProbeAttempts; i++ {
		if !work.available(now) {
			t.Fatal("attempt budget prematurely exhausted", i)
		}
		work.attempts++
	}
	if work.available(now.Add(tcpProbeInterval - time.Nanosecond)) {
		t.Fatal("attempt budget exceeded")
	}
	if !work.available(now.Add(tcpProbeInterval)) {
		t.Fatal("attempt budget failed to recover")
	}
	work.packets = tcpProbePackets
	if work.available(now.Add(tcpProbeInterval + time.Millisecond)) {
		t.Fatal("packet budget exceeded")
	}
	if work.available(now) {
		t.Fatal("backwards clock replenished budget")
	}
	if !work.available(now.Add(2 * tcpProbeInterval)) {
		t.Fatal("packet budget failed to recover")
	}
}

func TestTCPProbeDispatchRotatesAndSharesBudgetAcrossProofs(t *testing.T) {
	flow := &FlowStack{mtu: 1280, tcpProofSerial: 1, tcpConnections: make(map[*flowTCPConn]struct{})}
	// Nil adapter endpoints reject safely, allowing the attempt bound and
	// rotation to be measured independently of TCP's eligibility guards.
	for id := uint64(1); id <= 100; id++ {
		flow.tcpConnections[&flowTCPConn{owner: flow, id: id}] = struct{}{}
	}
	proof := tcpPathProof{owner: flow, serial: 1, size: 1280, verifiedAt: time.Now()}
	if n := flow.dispatchTCPPathProof(proof); n != 0 {
		t.Fatal("nil endpoint transmitted")
	}
	if flow.tcpProbeCursor != 64 || flow.tcpProbeBudget.attempts != 64 {
		t.Fatal("first batch not bounded", flow.tcpProbeCursor)
	}
	flow.tcpProofSerial++
	proof.serial++
	flow.dispatchTCPPathProof(proof)
	if flow.tcpProbeCursor != 64 {
		t.Fatal("new proof replenished shared budget")
	}
	flow.tcpProbeBudget.start = time.Now().Add(-tcpProbeInterval)
	proof.verifiedAt = time.Now()
	flow.dispatchTCPPathProof(proof)
	if flow.tcpProbeCursor != 28 || flow.tcpProbeBudget.attempts != 64 {
		t.Fatal("rotation starved later sockets", flow.tcpProbeCursor)
	}
}
