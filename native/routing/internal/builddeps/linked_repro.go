//go:build amnezia_dependency_repro

package builddeps

// Explicitly non-release mode for negative tests against pristine upstream.
// Its provenance is rejected by the release/package verification gate.
func linkedSource() (string, string, string, string) { return "", "", "", "reproduction" }

func allowReproduction() bool { return true }
