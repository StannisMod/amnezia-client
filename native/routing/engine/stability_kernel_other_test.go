//go:build !linux || android

package engine

import (
	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"net"
	"net/netip"
	"testing"
)

func stabilityKernelPeer(t *testing.T, _ awg.Config) (netip.AddrPort, net.Listener) {
	t.Fatal("independent kernel TCP fixture requires Linux")
	return netip.AddrPort{}, nil
}

func stabilityStartNative(t *testing.T, _ []byte) func() error { t.Fatal("requires Linux"); return nil }
func stabilityNativeBlackhole(t *testing.T, _ bool, _ netip.AddrPort) uint64 {
	t.Fatal("requires Linux")
	return 0
}
func stabilityNativeImpairment(t *testing.T, _ bool) { t.Fatal("requires Linux") }
