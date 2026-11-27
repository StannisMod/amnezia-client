package dnsguard

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// Test-only proof for Android's prospective native-engine DNS path. A TCP
// listener is NOT a safe port lease: it would expose a new service. Bind a
// socket without listen/connect and retain it until the DNS flow is joined.
func TestDNSNativeTunnelPortLeaseNeedsNeitherListenerNorNetworkBind(t *testing.T) {
	for _, kind := range []int{unix.SOCK_DGRAM, unix.SOCK_STREAM} {
		fd, err := unix.Socket(unix.AF_INET, kind|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer unix.Close(fd)
			if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
				t.Fatal(err)
			}
			address, err := unix.Getsockname(fd)
			if err != nil {
				t.Fatal(err)
			}
			port := address.(*unix.SockaddrInet4).Port
			if port == 0 {
				t.Fatal("kernel did not reserve a port")
			}
			if _, err := unix.Getpeername(fd); !errors.Is(err, unix.ENOTCONN) {
				t.Fatalf("reservation unexpectedly connected: %v", err)
			}
			listener, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
			if err != nil || listener != 0 {
				t.Fatalf("reservation exposed a listener: %d / %v", listener, err)
			}
			competitor, err := unix.Socket(unix.AF_INET, kind|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(competitor)
			// Wildcard reservation protects the same protocol/port on the
			// original tunnel address too; loopback is a caller-owned stand-in.
			if err := unix.Bind(competitor, &unix.SockaddrInet4{
				Port: port, Addr: [4]byte{127, 0, 0, 1},
			}); !errors.Is(err, unix.EADDRINUSE) {
				t.Fatalf("another native/kernel flow could reuse leased port: %v", err)
			}
		}()
	}
}
