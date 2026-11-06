//go:build stability_trace

package awg

import "gvisor.dev/gvisor/pkg/tcpip/stack"

// StabilityProbe is available only in an explicitly tagged diagnostic build.
// It observes the existing stack; no timer, window or recovery option changes.
func (s *FlowStack) StabilityProbe(probe stack.TCPProbeFunc) {
	s.stack.AddTCPProbe(probe)
}
