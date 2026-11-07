//go:build linux && !android

package engine

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A real address removal with the replacement protected route verified.
func stabilityNativeAddressMove(t *testing.T) {
	t.Helper()
	mode := os.Getenv("AMNEZIA_STABILITY_LAB")
	if mode != "isolated-container" && mode != "isolated-namespace" {
		t.Fatal("address move requires the isolated native fixture")
	}
	run := func(args ...string) {
		t.Helper()
		if b, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			t.Fatalf("ip %v: %v %s", args, e, b)
		}
	}
	t.Cleanup(func() {
		exec.Command("ip", "addr", "del", "203.0.113.3/24", "dev", "stb-underlay").Run()
		exec.Command("ip", "addr", "add", "203.0.113.1/24", "dev", "stb-underlay").Run()
		exec.Command("ip", "route", "replace", "default", "via", "203.0.113.2", "dev", "stb-underlay").Run()
	})

	run("addr", "del", "203.0.113.1/24", "dev", "stb-underlay")
	run("addr", "add", "203.0.113.3/24", "dev", "stb-underlay")
	run("route", "replace", "default", "via", "203.0.113.2", "dev", "stb-underlay")
	physical, err := exec.Command("ip", "route", "get", "203.0.113.2", "mark", "0x40000000").CombinedOutput()
	if err != nil || !strings.Contains(string(physical), "src 203.0.113.3") {
		t.Fatalf("replacement underlay is not usable: %v %s", err, physical)
	}
	t.Logf("replacement protected route: %s", physical)
	b, e := exec.Command("ip", "route", "get", "203.0.113.1", "from", "10.77.0.2", "iif", stabilityCaptureInterface).CombinedOutput()
	t.Logf("return path after address removal: err=%v %s", e, b)
}

const stabilityCaptureInterface = "amnrouting0"

func stabilityNativeRemoveDefault(t *testing.T) {
	t.Helper()
	mode := os.Getenv("AMNEZIA_STABILITY_LAB")
	if mode != "isolated-container" && mode != "isolated-namespace" {
		t.Fatal("default removal requires isolated native fixture")
	}
	if b, e := exec.Command("ip", "route", "del", "default", "via", "203.0.113.2", "dev", "stb-underlay").CombinedOutput(); e != nil {
		t.Fatalf("remove owned default: %v %s", e, b)
	}
	t.Cleanup(func() {
		exec.Command("ip", "route", "replace", "default", "via", "203.0.113.2", "dev", "stb-underlay").Run()
	})
	b, e := exec.Command("ip", "route", "get", "203.0.113.2", "mark", "0x40000000").CombinedOutput()
	if e != nil || !strings.Contains(string(b), "dev stb-underlay") {
		t.Fatalf("VPN endpoint lost native path: %v %s", e, b)
	}
	t.Logf("VPN server remains reachable without native default: %s", b)
}

// Diagnostic application-side equivalent of marking before connect's first
// route lookup. Production applications must not need this callback.
func stabilityNativeApplicationDial(ctx context.Context, address string, early bool) (net.Conn, error) {
	d := net.Dialer{}
	if early {
		d.Control = func(_, _ string, raw syscall.RawConn) error {
			var inner error
			err := raw.Control(func(fd uintptr) { inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 0x20000000) })
			if err != nil {
				return err
			}
			return inner
		}
	}
	return d.DialContext(ctx, "tcp", address)
}

// Move the endpoint path to a different physical interface/gateway/prefix,
// retaining the server's public address on its loopback. The old pair is
// deleted; continuing traffic cannot accidentally use the retired interface.
func stabilityNativeInterfaceMove(t *testing.T) {
	t.Helper()
	mode := os.Getenv("AMNEZIA_STABILITY_LAB")
	if mode != "isolated-container" && mode != "isolated-namespace" {
		t.Fatal("interface move requires isolated native fixture")
	}
	run := func(args ...string) {
		t.Helper()
		if b, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			t.Fatalf("ip %v: %v %s", args, e, b)
		}
	}
	run("link", "add", "stb-alt", "type", "veth", "peer", "name", "eth1", "netns", "stability-peer")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "stb-alt").Run() })
	run("addr", "add", "198.51.100.1/24", "dev", "stb-alt")
	run("link", "set", "stb-alt", "up")
	run("-n", "stability-peer", "addr", "add", "198.51.100.2/24", "dev", "eth1")
	run("-n", "stability-peer", "link", "set", "eth1", "up")
	if dir := os.Getenv("AMNEZIA_STABILITY_TRACE"); dir != "" {
		if e := os.MkdirAll(dir, 0755); e != nil {
			t.Fatal(e)
		}
		f, e := os.Create(filepath.Join(dir, "interface-outer.txt"))
		if e != nil {
			t.Fatal(e)
		}
		capture := exec.Command("tcpdump", "-i", "stb-alt", "-n", "-l", "udp")
		capture.Stdout = f
		capture.Stderr = f
		if e = capture.Start(); e != nil {
			f.Close()
			t.Fatal(e)
		}
		t.Cleanup(func() { capture.Process.Kill(); capture.Wait(); f.Close() })
	}
	run("-n", "stability-peer", "addr", "add", "203.0.113.2/32", "dev", "lo")
	// Keep the server public source stable: this fixture changes the client
	// uplink, not the configured cryptographic peer endpoint.
	run("-n", "stability-peer", "route", "replace", "198.51.100.1/32", "dev", "eth1", "src", "203.0.113.2")
	reply, e := exec.Command("ip", "-n", "stability-peer", "route", "get", "198.51.100.1").CombinedOutput()
	if e != nil || !strings.Contains(string(reply), "src 203.0.113.2") {
		t.Fatalf("peer public source changed: %v %s", e, reply)
	}
	run("route", "replace", "203.0.113.2/32", "via", "198.51.100.2", "dev", "stb-alt", "src", "198.51.100.1")
	run("link", "del", "stb-underlay")
	b, e := exec.Command("ip", "route", "get", "203.0.113.2", "mark", "0x40000000").CombinedOutput()
	if e != nil || !strings.Contains(string(b), "via 198.51.100.2 dev stb-alt src 198.51.100.1") {
		t.Fatalf("new interface/gateway path unavailable: %v %s", e, b)
	}
	t.Logf("new protected interface/gateway/prefix: %s", b)
}
