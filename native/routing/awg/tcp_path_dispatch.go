package awg

import (
	"sort"
	"time"
)

// Bound both work on healthy sockets and actual extra packets across the entire
// peer. A new path proof does not replenish the budget.
const (
	tcpProbeInterval = time.Second
	tcpProbeAttempts = 64
	tcpProbePackets  = 4
)

type tcpProbeBudget struct {
	start             time.Time
	attempts, packets int
}

func (b *tcpProbeBudget) available(now time.Time) bool {
	if b.start.IsZero() || now.Sub(b.start) >= tcpProbeInterval {
		*b = tcpProbeBudget{start: now}
	}
	return now.Sub(b.start) >= 0 && b.attempts < tcpProbeAttempts && b.packets < tcpProbePackets
}

// dispatchTCPPathProof never holds state while invoking an endpoint: packet
// output re-enters state. The separate gate prevents MTU/network invalidation
// between validation and sending. The lifetime guard keeps the stack alive.
func (s *FlowStack) dispatchTCPPathProof(proof tcpPathProof) (sent int) {
	if !s.begin() {
		return 0
	}
	defer s.active.Done()
	s.tcpPathGate.Lock()
	defer s.tcpPathGate.Unlock()
	if !s.validTCPPathProof(proof, time.Now()) {
		return 0
	}
	s.state.Lock()
	connections := make([]*flowTCPConn, 0, len(s.tcpConnections))
	for conn := range s.tcpConnections {
		connections = append(connections, conn)
	}
	s.state.Unlock()
	sort.Slice(connections, func(i, j int) bool { return connections[i].id < connections[j].id })
	start := sort.Search(len(connections), func(i int) bool { return connections[i].id > s.tcpProbeCursor })
	for offset := 0; offset < len(connections); offset++ {
		now := time.Now()
		if !s.validTCPPathProof(proof, now) || !s.tcpProbeBudget.available(now) {
			break
		}
		conn := connections[(start+offset)%len(connections)]
		s.tcpProbeCursor = conn.id
		s.tcpProbeBudget.attempts++
		probe, supported := any(conn.TCPConn).(interface{ ProbeVerifiedPath(uint64) bool })
		if supported && probe.ProbeVerifiedPath(proof.serial) {
			s.tcpProbeBudget.packets++
			sent++
		}
	}
	return sent
}
