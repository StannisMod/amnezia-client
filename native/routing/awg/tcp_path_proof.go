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

type tcpPathOperation struct{ cancel context.CancelFunc }

// Caller holds state. Cancellation makes an obsolete size challenge retire
// promptly; generation checks remain mandatory even if a reply raced cancel.
func (s *FlowStack) invalidateTCPPathLocked(wake bool) {
	s.tcpPathGeneration++
	if s.tcpPathProbe != nil {
		s.tcpPathProbe.cancel()
	}
	if wake {
		select {
		case s.tcpPathWake <- struct{}{}:
		default:
		}
	}
}

func (s *FlowStack) invalidateTCPPath() {
	s.tcpPathGate.Lock()
	defer s.tcpPathGate.Unlock()
	s.state.Lock()
	s.invalidateTCPPathLocked(false)
	s.state.Unlock()
}

func (s *FlowStack) verifyTCPPath(ctx context.Context, peer netip.Addr) (tcpPathProof, error) {
	probeCtx, stop := context.WithCancel(ctx)
	defer stop()
	operation := &tcpPathOperation{cancel: stop}
	s.state.Lock()
	generation, size, closed := s.tcpPathGeneration, s.mtu, s.closed
	if !closed {
		s.tcpPathProbe = operation
	}
	s.state.Unlock()
	defer func() {
		s.state.Lock()
		if s.tcpPathProbe == operation {
			s.tcpPathProbe = nil
		}
		s.state.Unlock()
	}()
	if closed {
		return tcpPathProof{}, net.ErrClosed
	}
	if err := s.ProbePath(probeCtx, peer, size); err != nil {
		return tcpPathProof{}, err
	}
	s.state.Lock()
	defer s.state.Unlock()
	if err := probeCtx.Err(); err != nil {
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
	s.invalidateTCPPathLocked(false)
	s.state.Unlock()
	return func() { s.state.Lock(); s.invalidateTCPPathLocked(true); s.state.Unlock(); s.tcpPathGate.Unlock() }
}
