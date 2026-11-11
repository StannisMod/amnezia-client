//go:build amnezia_gvisor_2026

package engine

import "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

type stabilityTCPProbeFunc = tcp.TCPProbeFunc
type stabilityTCPEndpointState = tcp.TCPEndpointState
