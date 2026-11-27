//go:build cgo && amnezia_openvpn_dns

package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestCloakDNSPolicyDefaultAndGenerationOwnership(t *testing.T) {
	if AmneziaOpenVPNDNSIPv6Off() != 0 {
		t.Fatal("missing/default policy is not ON")
	}
	first := AmneziaOpenVPNDNSPolicy(1)
	if first <= 0 {
		t.Fatal("OFF policy not reserved")
	}
	t.Cleanup(func() { AmneziaOpenVPNDNSReleasePolicy(first) })
	if AmneziaOpenVPNDNSPolicy(0) > 0 || AmneziaOpenVPNDNSPolicy(1) > 0 {
		t.Fatal("replacement reserved an existing native generation")
	}
	if AmneziaOpenVPNDNSReleasePolicy(first+1) != 0 {
		t.Fatal("stale policy token released current native owner")
	}
	if AmneziaOpenVPNDNSReleasePolicy(first) != 1 || AmneziaOpenVPNDNSIPv6Off() != 1 {
		t.Fatal("confirmed retirement silently removed the effective OFF fence")
	}
	second := AmneziaOpenVPNDNSPolicy(0)
	if second <= first {
		t.Fatal("next connection did not get a distinct generation")
	}
	t.Cleanup(func() { AmneziaOpenVPNDNSReleasePolicy(second) })
	if AmneziaOpenVPNDNSIPv6Off() != 0 || AmneziaOpenVPNDNSReleasePolicy(first) != 0 {
		t.Fatal("old generation affected explicit next-connection ON")
	}
	if AmneziaOpenVPNDNSReleasePolicy(second) != 1 {
		t.Fatal("ON retirement failed")
	}
}

func TestCloakOFFRejectsHostnameAndIPv6BeforeResolverOrSocket(t *testing.T) {
	policy := AmneziaOpenVPNDNSPolicy(1)
	if policy <= 0 {
		t.Fatal("policy reserve failed")
	}
	t.Cleanup(func() { AmneziaOpenVPNDNSReleasePolicy(policy) })
	var resolutions, sockets atomic.Int32
	dialer := &amneziaCloakDialer{Dialer: net.Dialer{
		Resolver: &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			resolutions.Add(1)
			return nil, errors.New("fixture never opens a resolver socket")
		}},
		Control: func(string, string, syscall.RawConn) error {
			sockets.Add(1)
			return errors.New("fixture never connects")
		},
	}}
	for _, endpoint := range []string{"selected.invalid:443", "[fd77::1]:443", "[::ffff:127.0.0.1]:443", "invalid"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := dialer.DialContext(ctx, "tcp", endpoint)
		cancel()
		if conn != nil {
			conn.Close()
		}
		if err == nil {
			t.Fatalf("OFF accepted %q", endpoint)
		}
	}
	if resolutions.Load() != 0 || sockets.Load() != 0 {
		t.Fatalf("OFF bootstrap leaked into resolver/socket: dns=%d sockets=%d", resolutions.Load(), sockets.Load())
	}
	if amneziaCloakEndpointPolicy("198.51.100.1") != nil ||
		amneziaCloakSocketPolicy("tcp4", "198.51.100.1:443") != nil ||
		amneziaCloakSocketPolicy("tcp6", "[::ffff:198.51.100.1]:443") == nil {
		t.Fatal("numeric IPv4/native transport family fence changed")
	}
}

func TestCloakPolicyRetainsInflightNativeDial(t *testing.T) {
	policy := AmneziaOpenVPNDNSPolicy(1)
	if policy <= 0 {
		t.Fatal("policy reserve failed")
	}
	started, allowReturn := make(chan struct{}), make(chan struct{})
	var release sync.Once
	done := make(chan error, 1)
	t.Cleanup(func() {
		release.Do(func() { close(allowReturn) })
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fixture native dial cleanup did not join")
		}
		AmneziaOpenVPNDNSReleasePolicy(policy)
	})
	dialer := &amneziaCloakDialer{Dialer: net.Dialer{
		Control: func(network, endpoint string, _ syscall.RawConn) error {
			if err := amneziaCloakSocketPolicy(network, endpoint); err != nil {
				return err
			}
			close(started)
			<-allowReturn
			return errors.New("fixture stops before native connect")
		},
	}}
	go func() {
		defer close(done)
		conn, err := dialer.Dial("tcp", "127.0.0.1:9")
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("native IPv4 socket control was not reached")
	}
	if AmneziaOpenVPNDNSReleasePolicy(policy) != 0 {
		t.Fatal("policy retired an in-flight native dial")
	}
	release.Do(func() { close(allowReturn) })
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("fixture unexpectedly connected")
		}
	case <-time.After(time.Second):
		t.Fatal("native dial did not join")
	}
	if AmneziaOpenVPNDNSReleasePolicy(policy) != 1 {
		t.Fatal("joined native dial retained orphan policy")
	}
}

func TestCloakONPreservesEndpointPolicy(t *testing.T) {
	policy := AmneziaOpenVPNDNSPolicy(0)
	if policy <= 0 {
		t.Fatal("ON reserve failed")
	}
	defer AmneziaOpenVPNDNSReleasePolicy(policy)
	for _, host := range []string{"selected.invalid", "fd77::1", "198.51.100.1"} {
		if amneziaCloakEndpointPolicy(host) != nil {
			t.Fatalf("ON endpoint validation changed for %q", host)
		}
	}
	if amneziaCloakSocketPolicy("tcp6", "[fd77::1]:443") != nil {
		t.Fatal("ON IPv6 native transport changed")
	}
}
