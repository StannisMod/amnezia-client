//go:build darwin

package nativedns

import "golang.org/x/sys/unix"

func bindInterface(fd uintptr, name string, index int) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
}
