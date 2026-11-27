//go:build linux && with_gvisor

package mobile

import (
	"context"
	"github.com/sagernet/sing-box/adapter"
	"golang.org/x/sys/unix"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnexpectedPacketReaderExitIsReported(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[1])
	var released atomic.Int32
	platform, err := New(pair[0], Hooks{Protect: func(int) error { return nil }, Release: func() { released.Add(1) }, Interfaces: func() ([]adapter.NetworkInterface, error) { return nil, nil }})
	if err != nil {
		unix.Close(pair[0])
		t.Fatal(err)
	}
	session, err := StartWithNetworkDNS(context.Background(), platform, sampleConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err = session.Stats(); err != nil {
		t.Fatal(err)
	}
	if err = platform.capture.(*packetDescriptor).file.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err = session.Stats(); err != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err == nil {
		t.Fatalf("dead packet capture still reported healthy: capture=%T", platform.capture)
	}
	if released.Load() != 0 {
		t.Fatal("reader failure released JNI host before explicit close")
	}
	session.Close()
	if released.Load() != 1 {
		t.Fatal("host not released exactly once")
	}
}
