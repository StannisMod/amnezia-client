//go:build windows

package nativedns

import (
	"golang.org/x/sys/windows"
	"math/bits"
)

func bindInterface(fd uintptr, name string, index int) error {
	// Windows IP_UNICAST_IF takes an IPv4 interface index in network order.
	// ws2ipdef.h defines IP_UNICAST_IF as 31; x/sys/windows does not export it.
	const ipUnicastIF = 31
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIF, int(bits.ReverseBytes32(uint32(index))))
}
