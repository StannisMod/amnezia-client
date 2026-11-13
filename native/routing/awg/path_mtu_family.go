package awg

import (
	"errors"
	"net/netip"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Each IP endpoint sees its own MTU while retaining the same private NIC,
// addresses and connections. IPv4 reductions must not disable IPv6 or inherit
// IPv6's 1280-byte minimum. No OS TUN or peer is replaced.
type flowMTUProtocol struct {
	stack.MulticastForwardingNetworkProtocol
	mtu *atomic.Uint32
}

type flowMTUNetworkInterface struct {
	stack.NetworkInterface
	mtu *atomic.Uint32
}

func (n *flowMTUNetworkInterface) MTU() uint32 { return n.mtu.Load() }
func (p *flowMTUProtocol) NewEndpoint(n stack.NetworkInterface, d stack.TransportDispatcher) stack.NetworkEndpoint {
	return p.MulticastForwardingNetworkProtocol.NewEndpoint(&flowMTUNetworkInterface{n, p.mtu}, d)
}

// Keep the optional forwarding/rejection interfaces of each IP protocol.
// Embedding these interfaces also accommodates the pinned Apple packet type.
type flowIPv4MTUProtocol struct {
	*flowMTUProtocol
	stack.RejectIPv4WithHandler
}
type flowIPv6MTUProtocol struct {
	*flowMTUProtocol
	stack.RejectIPv6WithHandler
}

func flowMTUFactory(factory stack.NetworkProtocolFactory, mtu *atomic.Uint32) stack.NetworkProtocolFactory {
	return func(s *stack.Stack) stack.NetworkProtocol {
		base := factory(s)
		common := &flowMTUProtocol{base.(stack.MulticastForwardingNetworkProtocol), mtu}
		if reject, ok := base.(stack.RejectIPv4WithHandler); ok {
			return &flowIPv4MTUProtocol{common, reject}
		}
		return &flowIPv6MTUProtocol{common, base.(stack.RejectIPv6WithHandler)}
	}
}

// Caller holds state. The maximum remains the TUN's packet-buffer ceiling;
// a path measurement and TCP proof use the selected family's smaller limit.
func (s *FlowStack) pathMTULocked(peer netip.Addr) int {
	if peer.Unmap().Is4() && s.has4 {
		return int(s.mtu4.Load())
	}
	if peer.Is6() && s.has6 {
		return int(s.mtu6.Load())
	}
	return s.mtu
}
func (s *FlowStack) pathMTU(peer netip.Addr) int {
	s.state.Lock()
	defer s.state.Unlock()
	return s.pathMTULocked(peer)
}
func (s *FlowStack) setFamilyPathMTU(peer netip.Addr, mtu int) error {
	peer = peer.Unmap()
	if !peer.IsValid() {
		return errors.New("invalid MTU peer family")
	}
	return s.setPathMTU(peer, mtu)
}
func minimumPathMTU(peer netip.Addr) int {
	if peer.Is6() {
		return 1280
	}
	return 576
}
