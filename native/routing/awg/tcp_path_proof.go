package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// tcpPathProof is deliberately private: a caller-supplied sequence number is
// not evidence that the current encrypted path can carry full-sized packets.
type tcpPathProof struct {
	owner              *FlowStack
	generation, serial uint64
	size               int
	verifiedAt         time.Time
}

const tcpPathProofLifetime = time.Second

func (s *FlowStack) invalidateTCPPath() {
	s.tcpPathGate.Lock()
	defer s.tcpPathGate.Unlock()
	s.state.Lock()
	s.tcpPathGeneration++
	s.state.Unlock()
}

func (s *FlowStack) verifyTCPPath(ctx context.Context, peer netip.Addr) (tcpPathProof, error) {
	s.state.Lock()
	generation, size, closed := s.tcpPathGeneration, s.mtu, s.closed
	s.state.Unlock()
	if closed {
		return tcpPathProof{}, net.ErrClosed
	}
	if err := s.ProbePath(ctx, peer, size); err != nil {
		return tcpPathProof{}, err
	}
	s.state.Lock()
	defer s.state.Unlock()
	if err := ctx.Err(); err != nil {
		return tcpPathProof{}, err
	}
	if s.closed {
		return tcpPathProof{}, net.ErrClosed
	}
	if generation != s.tcpPathGeneration || size != s.mtu {
		return tcpPathProof{}, errors.New("TCP path changed during verification")
	}
	if s.tcpProofSerial == ^uint64(0) {
		return tcpPathProof{}, errors.New("TCP path proof sequence exhausted")
	}
	s.tcpProofSerial++
	return tcpPathProof{s, generation, s.tcpProofSerial, size, time.Now()}, nil
}

// Validation must also be repeated when dispatching a probe. It never grants
// permission to reset the TCP retransmission timer or its normal retry budget.
func (s *FlowStack) validTCPPathProof(proof tcpPathProof, now time.Time) bool {
	s.state.Lock()
	defer s.state.Unlock()
	age := now.Sub(proof.verifiedAt)
	return !s.closed && proof.owner == s && proof.serial != 0 &&
		proof.serial == s.tcpProofSerial && proof.generation == s.tcpPathGeneration &&
		proof.size == s.mtu && age >= 0 && age <= tcpPathProofLifetime
}

// Serialize dispatch with the whole rebind operation. Invalidate on both edges
// so a challenge started during the operation cannot describe the retired path.
func (s *FlowStack) beginTCPPathChange() func() {
	s.tcpPathGate.Lock()
	s.state.Lock()
	s.tcpPathGeneration++
	s.state.Unlock()
	return func() { s.state.Lock(); s.tcpPathGeneration++; s.state.Unlock(); s.tcpPathGate.Unlock() }
}
