package dnsguard

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func TestPacketEndpointRejectsNonUnicastCapture(t *testing.T) {
	for _, raw := range []string{"", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "fe80::1%wlan0"} {
		address, _ := netip.ParseAddr(raw)
		if endpoint, err := newPacketEndpoint(address); err == nil || endpoint != nil {
			if endpoint != nil {
				_ = endpoint.Close()
			}
			t.Fatalf("accepted invalid capture %q", raw)
		}
	}
}

func TestPacketEndpointCloseJoinsBlockedReader(t *testing.T) {
	for _, raw := range []string{"198.19.255.1", "fd00::53"} {
		t.Run(raw, func(t *testing.T) {
			endpoint, err := newPacketEndpoint(netip.MustParseAddr(raw))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = endpoint.Close() })
			reader := make(chan error, 1)
			go func() {
				_, err := endpoint.Read([][]byte{make([]byte, 65535)}, make([]int, 1), 0)
				reader <- err
			}()
			closed := make(chan struct{})
			go func() {
				var concurrent sync.WaitGroup
				for i := 0; i < 8; i++ {
					concurrent.Add(1)
					go func() { defer concurrent.Done(); _ = endpoint.Close() }()
				}
				concurrent.Wait()
				close(closed)
			}()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("close did not join blocked reader")
			}
			if err := <-reader; !errors.Is(err, os.ErrClosed) {
				t.Fatalf("blocked read returned %v", err)
			}
			if _, err := endpoint.Write([][]byte{{0x45}}, 0); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("closed endpoint accepted input: %v", err)
			}
			if _, err := endpoint.listenTCP(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("closed endpoint admitted TCP: %v", err)
			}
			if _, err := endpoint.listenUDP(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("closed endpoint admitted UDP: %v", err)
			}
		})
	}
}

func TestPacketEndpointNeverAdmitsOtherDestination(t *testing.T) {
	endpoint, err := newPacketEndpoint(netip.MustParseAddr("198.19.255.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	original := []byte{9, 8, 7, 0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0,
		10, 0, 0, 1, 198, 19, 255, 2}
	unchanged := append([]byte(nil), original...)
	if count, err := endpoint.Write([][]byte{original}, 3); count != 1 || err != nil {
		t.Fatalf("non-owned input count=%d err=%v", count, err)
	}
	for i := range original {
		if original[i] != unchanged[i] {
			t.Fatal("borrowed native packet/headroom changed")
		}
	}
	if count, err := endpoint.Write([][]byte{original}, -1); count != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("invalid headroom count=%d err=%v", count, err)
	}
	// The input is not injected into the private stack at all. Its output queue
	// and notifier must remain empty, not emit an alternate route/error packet.
	if packet := endpoint.link.Read(); packet != nil {
		packet.DecRef()
		t.Fatal("non-owned destination produced stack output")
	}
	select {
	case <-endpoint.outputWake:
		t.Fatal("non-owned destination woke packet output")
	default:
	}
}
