//go:build windows

package desktop

import (
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"
)

// MIB_UNICASTIPADDRESS_ROW from netioapi.h. The explicit padding keeps the
// LUID aligned on both Windows architectures supported by this helper.
type winUnicastAddress struct {
	Address           winSockaddr
	_                 [4]byte
	LUID              uint64
	Index             uint32
	PrefixOrigin      uint32
	SuffixOrigin      uint32
	ValidLifetime     uint32
	PreferredLifetime uint32
	PrefixLength      uint8
	SkipAsSource      bool
	_                 [2]byte
	DadState          uint32
	ScopeID           uint32
	Created           int64
}

var initializeUnicastAddress = ipHelper.NewProc("InitializeUnicastIpAddressEntry")
var deleteUnicastAddress = ipHelper.NewProc("DeleteUnicastIpAddressEntry")
var createUnicastAddress = ipHelper.NewProc("CreateUnicastIpAddressEntry")
var getUnicastAddress = ipHelper.NewProc("GetUnicastIpAddressEntry")

// sing-tun installs addresses before disabling DAD. Windows can already have
// scheduled a probe at that point; gVisor owns the same address and answers it,
// leaving the host address Duplicate. Recreate only our adapter's configured
// IPv6 addresses after tun.New has disabled DAD and before starting the stack.
func prepareCaptureIPv6(luid uint64, prefixes []netip.Prefix) error {
	for _, prefix := range prefixes {
		row := winUnicastAddress{}
		initializeUnicastAddress.Call(uintptr(unsafe.Pointer(&row)))
		row.Address = sockAddress(prefix.Addr())
		row.LUID = luid
		status, _, _ := deleteUnicastAddress.Call(uintptr(unsafe.Pointer(&row)))
		if status != 0 {
			return fmt.Errorf("remove capture IPv6 address: %w", syscall.Errno(status))
		}
		row.PrefixLength = uint8(prefix.Bits())
		row.ValidLifetime = ^uint32(0)
		row.PreferredLifetime = ^uint32(0)
		row.DadState = 4 // IpDadStatePreferred; optimistic DAD is disabled by tun.New.
		status, _, _ = createUnicastAddress.Call(uintptr(unsafe.Pointer(&row)))
		if status != 0 {
			return fmt.Errorf("create capture IPv6 address: %w", syscall.Errno(status))
		}
		status, _, _ = getUnicastAddress.Call(uintptr(unsafe.Pointer(&row)))
		if status != 0 {
			return fmt.Errorf("inspect capture IPv6 address: %w", syscall.Errno(status))
		}
		if row.DadState != 4 {
			return fmt.Errorf("capture IPv6 address is not ready (DAD state %d)", row.DadState)
		}
	}
	return nil
}
