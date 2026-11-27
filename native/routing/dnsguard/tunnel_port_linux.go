package dnsguard

import (
	"os"

	"github.com/StannisMod/amnezia-client/native/routing/nativedns"
	"golang.org/x/sys/unix"
)

func reserveTunnelPort(network string) (*os.File, uint16, error) {
	kind := unix.SOCK_DGRAM
	if network == "tcp4" {
		kind = unix.SOCK_STREAM
	} else if network != "udp4" {
		return nil, 0, nativedns.ErrScopeUnavailable
	}
	fd, err := unix.Socket(unix.AF_INET, kind|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	lease := os.NewFile(uintptr(fd), "native-dns-port-reservation")
	if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
		lease.Close()
		return nil, 0, err
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		lease.Close()
		return nil, 0, err
	}
	return lease, uint16(bound.(*unix.SockaddrInet4).Port), nil
}
