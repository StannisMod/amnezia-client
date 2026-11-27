//go:build !linux && !darwin && !windows

package nativedns

func bindInterface(uintptr, string, int) error { return ErrScopeUnavailable }
