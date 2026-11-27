//go:build amnezia_native_dns_runtime_probe

package libXray

// Test-only fault entry. This file is NOT exported by the Conan recipe.
// The runtime probe AAR is explicitly tagged/labeled and never shipped.
func ProbeAbortNativeDNS() string {
	androidDNS.Lock()
	s := androidDNS.session
	running := androidDNS.running
	androidDNS.Unlock()
	if s == nil || !running {
		return "no admitted native DNS generation"
	}
	// Deliberately fail the real prepared UDP/TCP owner without setting the
	// intentional-stop flag. Production failure notification/cleanup runs.
	_ = s.flows.Close()
	return ""
}

func ProbeNativeDNSOwned() bool {
	androidDNS.Lock()
	defer androidDNS.Unlock()
	return androidDNS.running || androidDNS.session != nil
}
