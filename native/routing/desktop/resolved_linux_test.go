//go:build linux && !android

package desktop

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/godbus/dbus/v5"
	"net/netip"
)

func TestNetworkDNSRecoveryRetiresUnavailableInventoryAndRetries(t *testing.T) {
	links := []networkDNSLink{{Index: 7, Name: "uplink-a", Servers: []dnspolicy.NetworkServer{{Address: netip.MustParseAddr("192.0.2.53")}}}}
	freezes, reloads := 0, 0
	fail := false
	r := &networkDNSRecovery{fingerprint: networkDNSFingerprint(links), suspend: func() { freezes++ }, reload: func(_ []networkDNSLink) error {
		reloads++
		if fail {
			return errors.New("invalid inventory")
		}
		return nil
	}}
	if err := r.update(links, nil); err != nil || freezes != 0 || reloads != 0 {
		t.Fatal("duplicate inventory disturbed DNS")
	}
	if r.update(nil, errors.New("bus unavailable")) == nil || freezes != 1 || reloads != 0 {
		t.Fatal("bus loss retained old DNS")
	}
	// Same addresses after a bus/network interruption still need fresh sockets
	// and cache: equal DNS addresses do not establish network identity.
	if err := r.update(links, nil); err != nil || reloads != 1 {
		t.Fatal("recovery reused retired generation")
	}
	links[0].Name = "uplink-b"
	fail = true
	if r.update(links, nil) == nil || r.fingerprint != "" {
		t.Fatal("invalid candidate was published")
	}
	fail = false
	if err := r.update(links, nil); err != nil || reloads != 3 {
		t.Fatal("failed replacement was not retried")
	}
	if err := r.update(links, nil); err != nil || reloads != 3 {
		t.Fatal("successful generation was repeatedly replaced")
	}
}

func TestResolvedLinkRetriesSetterRace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	err := waitResolvedLink(ctx, func() error {
		calls++
		if calls == 1 {
			// GetLink succeeded, but resolved removed its object before the
			// setter. The wrapped D-Bus error must still be recognized.
			return fmt.Errorf("SetLinkDNS: %w", dbus.Error{Name: resolvedService + ".NoSuchLink"})
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("startup did not recover a transient setter race: calls=%d err=%v", calls, err)
	}
}

func TestResolvedLinkDoesNotRetryPermanentFailures(t *testing.T) {
	for _, name := range []string{"org.freedesktop.DBus.Error.AccessDenied", resolvedService + ".LinkBusy"} {
		calls := 0
		failure := dbus.Error{Name: name, Body: []any{"private configuration must not be logged"}}
		err := waitResolvedLink(context.Background(), func() error { calls++; return failure })
		if calls != 1 || err == nil {
			t.Fatalf("permanent failure was retried: %s calls=%d err=%v", name, calls, err)
		}
		message := resolvedFailure("system resolver link configuration failed", err).Error()
		if !strings.Contains(message, name) || strings.Contains(message, "private configuration") {
			t.Fatalf("error must identify the category without exposing its body: %s", message)
		}
	}
}

func TestResolvedLinkStartupIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitResolvedLink(ctx, func() error { return dbus.Error{Name: resolvedService + ".NoSuchLink"} })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("startup ignored cancellation: %v", err)
	}
}
