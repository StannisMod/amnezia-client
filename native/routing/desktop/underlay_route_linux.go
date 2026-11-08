//go:build linux && !android

package desktop

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/sagernet/netlink/nl"
	"golang.org/x/sys/unix"
)

// Look up the endpoint with the same exemption mark as the real UDP socket.
// An unmarked/default-route lookup can instead select our own capture table or
// miss a destination-specific physical route. No routing state is modified.
func protectedRouteFingerprint(endpoint netip.AddrPort) (string, error) {
	if !endpoint.IsValid() {
		return "", errors.New("invalid protected route endpoint")
	}
	socket, err := nl.Subscribe(unix.NETLINK_ROUTE)
	if err != nil {
		return "", err
	}
	defer socket.Close()
	timeout := unix.Timeval{Sec: 1}
	if err = socket.SetSendTimeout(&timeout); err != nil {
		return "", err
	}
	if err = socket.SetReceiveTimeout(&timeout); err != nil {
		return "", err
	}
	req := nl.NewNetlinkRequest(unix.RTM_GETROUTE, unix.NLM_F_REQUEST)
	req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_ROUTE: {Socket: socket}}
	family, bits := unix.AF_INET, uint8(32)
	if endpoint.Addr().Is6() {
		family, bits = unix.AF_INET6, 128
	}
	msg := &nl.RtMsg{}
	msg.Family = uint8(family)
	msg.Dst_len = bits
	msg.Flags = unix.RTM_F_LOOKUP_TABLE
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(unix.RTA_DST, endpoint.Addr().AsSlice()))
	mark := make([]byte, 4)
	nl.NativeEndian().PutUint32(mark, socketMark)
	req.AddData(nl.NewRtAttr(unix.RTA_MARK, mark))
	req.AddData(nl.NewRtAttr(unix.RTA_IP_PROTO, []byte{unix.IPPROTO_UDP}))
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, endpoint.Port())
	req.AddData(nl.NewRtAttr(unix.RTA_DPORT, port))
	rows, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWROUTE)
	if err != nil {
		return "", err
	}
	if len(rows) != 1 || len(rows[0]) < unix.SizeofRtMsg {
		return "", errors.New("ambiguous protected endpoint route")
	}
	row := rows[0]
	route := nl.DeserializeRtMsg(row)
	if route.Type != unix.RTN_UNICAST && route.Type != unix.RTN_LOCAL {
		return "", errors.New("protected endpoint route unavailable")
	}
	attrs, err := nl.ParseRouteAttr(row[unix.SizeofRtMsg:])
	if err != nil {
		return "", err
	}
	var index uint32
	var gateway, source netip.Addr
	table := uint32(route.Table)
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case unix.RTA_OIF, unix.RTA_TABLE:
			if len(attr.Value) != 4 {
				return "", errors.New("invalid protected route attribute")
			}
			if attr.Attr.Type == unix.RTA_OIF {
				index = nl.NativeEndian().Uint32(attr.Value)
			} else {
				table = nl.NativeEndian().Uint32(attr.Value)
			}
		case unix.RTA_GATEWAY:
			gateway, _ = netip.AddrFromSlice(attr.Value)
		case unix.RTA_PREFSRC:
			source, _ = netip.AddrFromSlice(attr.Value)
		case unix.RTA_MULTIPATH:
			return "", errors.New("ambiguous protected endpoint nexthop")
		}
	}
	iface, err := net.InterfaceByIndex(int(index))
	if err != nil {
		return "", err
	}
	if iface.Name == InterfaceName || iface.Flags&net.FlagUp == 0 {
		return "", errors.New("protected endpoint route does not leave capture")
	}
	if !source.IsValid() || (source.IsLoopback() && iface.Flags&net.FlagLoopback == 0) || netip.MustParsePrefix("172.19.0.0/30").Contains(source.Unmap()) || netip.MustParsePrefix("fdfe:dcba:9876::/126").Contains(source.Unmap()) {
		return "", errors.New("protected endpoint has no usable native source")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	prefixes := make([]string, 0, len(addresses))
	for _, a := range addresses {
		prefixes = append(prefixes, a.String())
	}
	sort.Strings(prefixes)
	return fmt.Sprintf("%s/%d/%s/%s/%d/%d/%s", endpoint, index, source.Unmap(), gateway.Unmap(), table, iface.MTU, strings.Join(prefixes, ",")), nil
}
