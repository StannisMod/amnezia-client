//go:build windows

package desktop

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"golang.org/x/sys/windows"
)

// Microsoft netioapi.h ABI. These definitions deliberately stay small; route
// selection itself is performed by GetBestRoute2 on each native interface.
type winSockaddr struct {
	Family uint16
	Data   [26]byte
}
type winPrefix struct {
	Address winSockaddr
	Length  uint8
	_       [2]byte
}
type winRoute struct {
	LUID              uint64
	Index             uint32
	Destination       winPrefix
	NextHop           winSockaddr
	SitePrefixLength  uint8
	ValidLifetime     uint32
	PreferredLifetime uint32
	Metric            uint32
	Protocol          uint32
	Loopback          bool
	Autoconfigure     bool
	Publish           bool
	Immortal          bool
	Age               uint32
	Origin            uint32
}

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var bestRoute2 = ipHelper.NewProc("GetBestRoute2")
var getRouteTable2 = ipHelper.NewProc("GetIpForwardTable2")
var freeMibTable = ipHelper.NewProc("FreeMibTable")
var initRoute2 = ipHelper.NewProc("InitializeIpForwardEntry")
var createRoute2 = ipHelper.NewProc("CreateIpForwardEntry2")

func sockAddress(address netip.Addr) winSockaddr {
	var raw winSockaddr
	if address.Is4() {
		v := windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: address.As4()}
		*(*windows.RawSockaddrInet4)(unsafe.Pointer(&raw)) = v
	} else {
		v := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: address.As16()}
		*(*windows.RawSockaddrInet6)(unsafe.Pointer(&raw)) = v
	}
	return raw
}

func (p winPrefix) prefix() netip.Prefix {
	switch p.Address.Family {
	case windows.AF_INET:
		if p.Length > 32 {
			return netip.Prefix{}
		}
		return netip.PrefixFrom(netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&p.Address)).Addr), int(p.Length))
	case windows.AF_INET6:
		if p.Length > 128 {
			return netip.Prefix{}
		}
		return netip.PrefixFrom(netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(&p.Address)).Addr), int(p.Length))
	}
	return netip.Prefix{}
}

func nativeRoute(destination netip.Addr, excluded string) (uint32, error) {
	if !destination.IsValid() {
		return 0, errors.New("native route lookup requires a numeric destination")
	}
	if destination.IsLoopback() {
		return 0, nil
	}
	var length uint32 = 32 << 10
	var storage []byte
	for attempt := 0; attempt < 3; attempt++ {
		storage = make([]byte, length)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&storage[0])), &length)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return 0, errors.New("native adapter inventory unavailable")
		}
		break
	}
	if length > uint32(len(storage)) {
		return 0, errors.New("native adapter inventory exceeds bound")
	}
	address := sockAddress(destination)
	bestBits := -1
	var bestMetric uint64
	var bestIndex uint32
	for adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&storage[0])); adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp || strings.EqualFold(windows.UTF16PtrToString(adapter.FriendlyName), excluded) {
			continue
		}
		var row winRoute
		var source winSockaddr
		luid := adapter.Luid
		status, _, _ := bestRoute2.Call(uintptr(unsafe.Pointer(&luid)), 0, 0, uintptr(unsafe.Pointer(&address)), 0, uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&source)))
		if status != 0 {
			continue
		}
		prefix := row.Destination.prefix()
		if !prefix.IsValid() || !prefix.Contains(destination) {
			continue
		}
		metric := adapter.Ipv4Metric
		if destination.Is6() {
			metric = adapter.Ipv6Metric
		}
		total := uint64(row.Metric) + uint64(metric)
		if prefix.Bits() > bestBits || prefix.Bits() == bestBits && (total < bestMetric || total == bestMetric && row.Index < bestIndex) {
			bestBits = prefix.Bits()
			bestMetric = total
			bestIndex = row.Index
		}
	}
	runtime.KeepAlive(storage)
	if bestIndex == 0 {
		return 0, errors.New("no native route outside the capture adapter")
	}
	return bestIndex, nil
}

func protectRoute(raw syscall.RawConn, destination netip.Addr, excluded string) error {
	index, err := nativeRoute(destination, excluded)
	if err != nil {
		return err
	}
	if index == 0 {
		return nil
	} // native loopback must remain local
	var inner error
	err = raw.Control(func(fd uintptr) {
		level := windows.IPPROTO_IPV6
		value := index
		if destination.Is4() {
			level = windows.IPPROTO_IP
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], index)
			value = *(*uint32)(unsafe.Pointer(&bytes[0]))
		}
		inner = windows.SetsockoptInt(windows.Handle(fd), level, 31, int(value)) // IP[_V6]_UNICAST_IF
	})
	if err != nil {
		return err
	}
	return inner
}

type windowsUnderlay struct{ closed atomic.Bool }

func (u *windowsUnderlay) factories() engine.Underlay {
	return engine.Underlay{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if u.closed.Load() {
				return nil, net.ErrClosed
			}
			destination, err := netip.ParseAddrPort(address)
			if err != nil {
				return nil, errors.New("native dial requires a numeric address")
			}
			dial := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
				if u.closed.Load() {
					return net.ErrClosed
				}
				return protectRoute(raw, destination.Addr(), InterfaceName)
			}}
			return dial.DialContext(ctx, network, address)
		},
		ListenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			if u.closed.Load() {
				return nil, net.ErrClosed
			}
			var config net.ListenConfig
			pc, err := config.ListenPacket(ctx, network, address)
			if err != nil {
				return nil, err
			}
			udp, ok := pc.(*net.UDPConn)
			if !ok {
				pc.Close()
				return nil, errors.New("native UDP host requires a socket handle")
			}
			return &windowsPacketConn{PacketConn: udp, udp: udp, owner: u}, nil
		},
	}
}

type windowsPacketConn struct {
	// Deliberately expose only PacketConn: syscall/UDP fast paths must not
	// bypass WriteTo's destination-aware protection before the first send.
	net.PacketConn
	udp   *net.UDPConn
	owner *windowsUnderlay
	mu    sync.Mutex
}

func (c *windowsPacketConn) WriteTo(data []byte, address net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.owner.closed.Load() {
		return 0, net.ErrClosed
	}
	destination, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return 0, errors.New("native UDP send requires a numeric destination")
	}
	raw, err := c.udp.SyscallConn()
	if err != nil {
		return 0, err
	}
	if err = protectRoute(raw, destination.Addr().Unmap(), InterfaceName); err != nil {
		return 0, err
	}
	return c.udp.WriteTo(data, address)
}

func routeTable() ([]winRoute, error) {
	var table unsafe.Pointer
	status, _, _ := getRouteTable2.Call(windows.AF_UNSPEC, uintptr(unsafe.Pointer(&table)))
	if status != 0 || table == nil {
		return nil, errors.New("native route table unavailable")
	}
	defer freeMibTable.Call(uintptr(table))
	count := *(*uint32)(table)
	if count > 1<<20 {
		return nil, errors.New("native route table exceeds bound")
	}
	rows := unsafe.Slice((*winRoute)(unsafe.Add(table, 8)), int(count))
	return append([]winRoute(nil), rows...), nil
}

func splitPrefix(prefix netip.Prefix) []netip.Prefix {
	bytes := prefix.Masked().Addr().AsSlice()
	bit := prefix.Bits()
	if bit >= len(bytes)*8 {
		return []netip.Prefix{prefix}
	}
	first := netip.PrefixFrom(prefix.Masked().Addr(), bit+1)
	bytes[bit/8] |= 1 << uint(7-bit%8)
	second, _ := netip.AddrFromSlice(bytes)
	return []netip.Prefix{first, netip.PrefixFrom(second, bit+1)}
}

// Mirror specific native networks with more-specific capture routes. Protected
// sockets still choose the untouched routes on their native interface. This
// prevents a literal-IP VPN rule being bypassed by a connected LAN route.
func captureSpecificRoutes(rows []winRoute, luid uint64) error {
	seen := map[netip.Prefix]bool{}
	for _, native := range rows {
		prefix := native.Destination.prefix()
		if native.Loopback || !prefix.IsValid() || prefix.Bits() == 0 || !prefix.Addr().IsGlobalUnicast() {
			continue
		}
		for _, capture := range splitPrefix(prefix) {
			if seen[capture] {
				continue
			}
			seen[capture] = true
			var row winRoute
			initRoute2.Call(uintptr(unsafe.Pointer(&row)))
			row.LUID = luid
			row.Destination = winPrefix{Address: sockAddress(capture.Addr()), Length: uint8(capture.Bits())}
			gateway := netip.MustParseAddr("172.19.0.2")
			if capture.Addr().Is6() {
				gateway = netip.MustParseAddr("fdfe:dcba:9876::2")
			}
			row.NextHop = sockAddress(gateway)
			row.Metric = 0
			status, _, _ := createRoute2.Call(uintptr(unsafe.Pointer(&row)))
			if status != 0 {
				return errors.New("specific native capture route installation failed")
			}
		}
	}
	return nil
}
