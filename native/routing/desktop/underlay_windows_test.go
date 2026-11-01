//go:build windows

package desktop

import (
	"net/netip"
	"syscall"
	"testing"
	"unsafe"
)

func TestNativeRouteABIAndLoopback(t *testing.T) {
	if _, unsafeFastPath := any(&windowsPacketConn{}).(syscall.Conn); unsafeFastPath {
		t.Fatal("UDP fast path can bypass native protection")
	}
	if unsafe.Sizeof(winSockaddr{}) != 28 || unsafe.Sizeof(winPrefix{}) != 32 || unsafe.Sizeof(winRoute{}) != 104 || unsafe.Offsetof(winRoute{}.NextHop) != 44 || unsafe.Offsetof(winRoute{}.Metric) != 84 {
		t.Fatal("Windows route API ABI changed")
	}
	if index, err := nativeRoute(netip.MustParseAddr("127.0.0.53"), InterfaceName); err != nil || index != 0 {
		t.Fatal("loopback must use its native local route", err)
	}
	if _, err := routeTable(); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeRoute(netip.MustParseAddr("1.1.1.1"), InterfaceName); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeRoute(netip.MustParseAddr("1.1.1.1"), ""); err != nil {
		t.Fatal(err)
	}
}
