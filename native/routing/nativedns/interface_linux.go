//go:build linux

package nativedns

import "golang.org/x/sys/unix"

func bindInterface(fd uintptr, name string, index int) error {
	return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
}
