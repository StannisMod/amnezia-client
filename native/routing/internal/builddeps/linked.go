//go:build !amnezia_dependency_repro

package builddeps

// This package exists only in the pinned backport. An unpatched dependency
// cannot compile a normal application, even outside our CI wrappers.
import "gvisor.dev/gvisor/pkg/amnezia"

func linkedSource() (string, string, string, string) {
	return amnezia.TCPRecoveryFix, amnezia.UpstreamVersion, amnezia.UpstreamCommit, "fixed"
}

func allowReproduction() bool { return false }
