package awg

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestIPv6PathProbeExactSizeAndLoweredLink(t *testing.T) {
	_, a, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("fd77::1")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, b, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("fd77::2")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var limit atomic.Int32
	limit.Store(1420)
	var badHeader atomic.Bool
	pump := func(from, to *FlowStack, filtered bool) {
		data := make([]byte, 65535)
		sizes := make([]int, 1)
		for {
			_, err := from.Read([][]byte{data}, sizes, 0)
			if err != nil {
				return
			}
			if filtered {
				if data[0]>>4 != 6 || data[6] != 58 {
					badHeader.Store(true)
				}
				if sizes[0] > int(limit.Load()) {
					continue
				}
			}
			if _, err := to.Write([][]byte{data[:sizes[0]]}, 0); err != nil {
				return
			}
		}
	}
	go pump(a, b, true)
	go pump(b, a, false)
	probe := func(size int, success bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		err := a.ProbePath(ctx, netip.MustParseAddr("fd77::2"), size)
		if (err == nil) != success {
			t.Fatalf("size %d success %v: %v", size, success, err)
		}
	}
	probe(1420, true)
	limit.Store(1340)
	probe(128, true)
	probe(1420, false)
	probe(1280, true)
	controller, err := NewPathMTUController(a, netip.MustParseAddr("fd77::2"))
	if err != nil {
		t.Fatal(err)
	}
	controller.timeout = 80 * time.Millisecond
	ctx, stop := context.WithTimeout(context.Background(), 4*time.Second)
	result, err := controller.Check(ctx)
	stop()
	if err != nil || result.State != "reduced" || result.After < 1280 || result.After > 1340 {
		t.Fatal("IPv6 regulation failed", result, err)
	}
	limit.Store(1200)
	ctx, stop = context.WithTimeout(context.Background(), 2*time.Second)
	unchanged, err := controller.Check(ctx)
	stop()
	if err != nil || unchanged.State != "inconclusive" || unchanged.After != result.After {
		t.Fatal("IPv6 minimum violation", unchanged, err)
	}
	if err := a.SetPathMTU(1280); err != nil {
		t.Fatal(err)
	}
	limit.Store(1420)
	probe(1420, true)
	if badHeader.Load() {
		t.Fatal("probe used a fragment or unexpected network header")
	}
	if err := a.SetPathMTU(1279); err == nil {
		t.Fatal("IPv6 MTU dropped below 1280")
	}
}

func TestPathProbeRejectsReassembledReply(t *testing.T) {
	_, a, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.79.0.1")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, b, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.79.0.2")}, 576)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var fragments atomic.Int32
	pump := func(from, to *FlowStack, response bool) {
		data := make([]byte, 65535)
		sizes := make([]int, 1)
		for {
			if _, err := from.Read([][]byte{data}, sizes, 0); err != nil {
				return
			}
			if response && sizes[0] >= 20 && data[0]>>4 == 4 && (data[6]&0x3f != 0 || data[7] != 0) {
				fragments.Add(1)
			}
			if _, err := to.Write([][]byte{data[:sizes[0]]}, 0); err != nil {
				return
			}
		}
	}
	go pump(a, b, false)
	go pump(b, a, true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := a.ProbePath(ctx, netip.MustParseAddr("10.79.0.2"), 1420); err == nil {
		t.Fatal("fragmented reverse path proved full-sized packet delivery")
	}
	if fragments.Load() < 2 {
		t.Fatal("test did not produce fragmented ICMP reply", fragments.Load())
	}
}
