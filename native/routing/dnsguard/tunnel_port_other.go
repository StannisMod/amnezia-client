//go:build !linux

package dnsguard

import (
	"os"

	"github.com/StannisMod/amnezia-client/native/routing/nativedns"
)

// This native-engine adapter is currently Android/Linux-only. Other adapters
// keep their original scoped exchange; no unreserved private-stack fallback.
func reserveTunnelPort(string) (*os.File, uint16, error) {
	return nil, 0, nativedns.ErrScopeUnavailable
}
