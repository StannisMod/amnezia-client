//go:build linux || android || darwin || ios

package mobile

import "golang.org/x/sys/unix"

func closeDescriptor(fd int) error { return unix.Close(fd) }
