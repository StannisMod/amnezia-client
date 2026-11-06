//go:build !amnezia_race_dependency

package builddeps

func allowRaceDependency() bool { return false }
