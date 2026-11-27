package nativedns

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

// InterfaceDial retains a native scope, not a path-selection heuristic. Callers
// must supply the original resolver's interface (VPN, explicit underlay, or lo).
// An unavailable/replaced interface or failed bind never uses a default route.
func InterfaceDial(name string, index int) (Dial, error) {
	if name == "" || index <= 0 {
		return nil, ErrScopeUnavailable
	}
	current, err := net.InterfaceByIndex(index)
	if err != nil || current.Name != name {
		return nil, ErrScopeUnavailable
	}
	return func(ctx context.Context, network string, server netip.AddrPort) (net.Conn, error) {
		if !server.IsValid() || !server.Addr().Is4() || server.Port() == 0 ||
			(network != "udp4" && network != "tcp4") {
			return nil, ErrScopeUnavailable
		}
		verify := func() bool {
			current, err := net.InterfaceByIndex(index)
			return err == nil && current.Name == name && current.Flags&net.FlagUp != 0
		}
		if !verify() {
			return nil, ErrScopeUnavailable
		}
		dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
			if !verify() {
				return ErrScopeUnavailable
			}
			var bound error
			if err := raw.Control(func(fd uintptr) { bound = bindInterface(fd, name, index) }); err != nil {
				return err
			}
			if bound != nil || !verify() {
				return ErrScopeUnavailable
			}
			return nil
		}}
		return dialer.DialContext(ctx, network, server.String())
	}, nil
}
