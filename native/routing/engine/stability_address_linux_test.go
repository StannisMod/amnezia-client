//go:build linux && !android

package engine

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
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
