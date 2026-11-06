//go:build amnezia_race_dependency

package builddeps

// Only tests built from prepare_race.py may use its verified private copies.
// Package/release verification rejects this tag even when the source is fixed.
func allowRaceDependency() bool { return true }
