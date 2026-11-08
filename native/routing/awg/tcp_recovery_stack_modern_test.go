//go:build amnezia_gvisor_2026

package awg

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func newTCPRecoveryTestStack(clock tcpip.Clock, processed func()) *stack.Stack {
	return stack.New(stack.Options{Clock: clock, NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocolProbe(func(*tcp.TCPEndpointState) { processed() })}})
}
