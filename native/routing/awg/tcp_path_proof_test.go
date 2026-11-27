package awg

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestTCPPathProofLifecycle(t *testing.T) {
	for _, addresses := range [][2]string{{"10.77.0.1", "10.77.0.2"}, {"fd77::1", "fd77::2"}} {
		t.Run(addresses[0], func(t *testing.T) {
			_, a, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr(addresses[0])}, 1420)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			_, b, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr(addresses[1])}, 1420)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			pump := func(from, to *FlowStack) {
				packet := make([]byte, 65535)
				sizes := make([]int, 1)
				for {
					if _, err := from.Read([][]byte{packet}, sizes, 0); err != nil {
						return
					}
					if _, err := to.Write([][]byte{packet[:sizes[0]]}, 0); err != nil {
						return
					}
				}
			}
			go pump(a, b)
			go pump(b, a)
			verify := func() tcpPathProof {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				p, err := a.verifyTCPPath(ctx, netip.MustParseAddr(addresses[1]))
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
			p := verify()
			if !a.validTCPPathProof(p, time.Now()) {
				t.Fatal("fresh challenge rejected")
			}
			if b.validTCPPathProof(p, time.Now()) {
				t.Fatal("foreign proof accepted")
			}
			if a.validTCPPathProof(p, p.verifiedAt.Add(tcpPathProofLifetime+time.Nanosecond)) {
				t.Fatal("expired proof accepted")
			}
			if a.validTCPPathProof(p, p.verifiedAt.Add(-time.Nanosecond)) {
				t.Fatal("future proof accepted")
			}
			q := verify()
			if a.validTCPPathProof(p, time.Now()) || !a.validTCPPathProof(q, time.Now()) {
				t.Fatal("superseded proof accepted")
			}
			a.invalidateTCPPath()
			if a.validTCPPathProof(q, time.Now()) {
				t.Fatal("old network proof accepted")
			}
			q = verify()
			if err := a.SetPathMTU(1280); err != nil {
				t.Fatal(err)
			}
			if a.validTCPPathProof(q, time.Now()) {
				t.Fatal("old MTU proof accepted")
			}
			q = verify()
			a.Close()
			if a.validTCPPathProof(q, time.Now()) {
				t.Fatal("closed path proof accepted")
			}
		})
	}
}

func TestTCPPathProofRejectsNetworkChangeDuringChallenge(t *testing.T) {
	_, a, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.78.0.1")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, b, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.78.0.2")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := a.verifyTCPPath(ctx, netip.MustParseAddr("10.78.0.2")); result <- err }()
	// Hold the actual outgoing challenge until after the network changes.
	request := make([]byte, 65535)
	sizes := make([]int, 1)
	if _, err := a.Read([][]byte{request}, sizes, 0); err != nil {
		t.Fatal(err)
	}
	a.invalidateTCPPath()
	writeResult := make(chan error, 1)
	requestSize := sizes[0]
	go func() { _, err := b.Write([][]byte{request[:requestSize]}, 0); writeResult <- err }()
	reply := make([]byte, 65535)
	if _, err := b.Read([][]byte{reply}, sizes, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([][]byte{reply[:sizes[0]]}, 0); err != nil {
		t.Fatal(err)
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("old network challenge issued a proof")
	}
	if a.tcpProofSerial != 0 {
		t.Fatal("failed challenge advanced proof serial")
	}
}

func TestMTUChangeCancelsCurrentProofWithoutLosingNewerOperation(t *testing.T) {
	_, flow, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.81.0.1")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	firstCtx, stopFirst := context.WithTimeout(context.Background(), time.Second)
	defer stopFirst()
	secondCtx, stopSecond := context.WithTimeout(context.Background(), time.Second)
	defer stopSecond()
	firstResult, secondResult := make(chan error, 1), make(chan error, 1)
	go func() { _, err := flow.verifyTCPPath(firstCtx, netip.MustParseAddr("10.81.0.2")); firstResult <- err }()
	operation := func() *tcpPathOperation { flow.state.Lock(); defer flow.state.Unlock(); return flow.tcpPathProbe }
	until := time.Now().Add(250 * time.Millisecond)
	for operation() == nil {
		if time.Now().After(until) {
			t.Fatal("first proof did not start")
		}
		time.Sleep(time.Millisecond)
	}
	first := operation()
	go func() { _, err := flow.verifyTCPPath(secondCtx, netip.MustParseAddr("10.81.0.2")); secondResult <- err }()
	until = time.Now().Add(250 * time.Millisecond)
	for operation() == first {
		if time.Now().After(until) {
			t.Fatal("second proof did not start")
		}
		time.Sleep(time.Millisecond)
	}
	stopFirst()
	select {
	case err := <-firstResult:
		if err != context.Canceled {
			t.Fatal("first proof", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("first cancellation blocked")
	}
	if operation() == nil {
		t.Fatal("old operation cleanup erased newer proof")
	}
	if err := flow.SetPathMTU(1280); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-secondResult:
		if err != context.Canceled {
			t.Fatal("current proof", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("MTU update waited for old probe deadline")
	}
	if operation() != nil {
		t.Fatal("completed proof retained cancellation state")
	}
}
