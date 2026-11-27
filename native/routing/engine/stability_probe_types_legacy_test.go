//go:build !amnezia_gvisor_2026

package engine

import "gvisor.dev/gvisor/pkg/tcpip/stack"

type stabilityTCPProbeFunc = stack.TCPProbeFunc
type stabilityTCPEndpointState = stack.TCPEndpointState
