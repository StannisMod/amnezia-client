//go:build !linux || android

package engine

import (
	"context"
	"errors"
	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"net"
	"net/netip"
	"testing"
)

func stabilityKernelPeer(t *testing.T, _ awg.Config) (netip.AddrPort, net.Listener) {
	t.Fatal("independent kernel TCP fixture requires Linux")
	return netip.AddrPort{}, nil
}

func stabilityStartNative(t *testing.T, _ []byte) (func() error, func() error) {
	t.Fatal("requires Linux")
	return nil, nil
}
func stabilityNativeBlackhole(t *testing.T, _ bool, _ netip.AddrPort) uint64 {
	t.Fatal("requires Linux")
	return 0
}
func stabilityNativeImpairment(t *testing.T, _ bool) { t.Fatal("requires Linux") }
func stabilityNativeAddressMove(t *testing.T)        { t.Fatal("requires Linux") }
func stabilityNativeRemoveDefault(t *testing.T)      { t.Fatal("requires Linux") }
func stabilityNativeApplicationDial(context.Context, string, bool) (net.Conn, error) {
	return nil, errors.New("requires Linux")
}
