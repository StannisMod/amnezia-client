//go:build linux && !android

package desktop

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// A private bus and a synthetic resolver: never connects to the host resolver.
type recoveryResolver struct {
	mu           sync.Mutex
	fail         atomic.Bool
	sets         atomic.Int32
	checks       atomic.Int32
	dns          []resolvedDNS
	domains      []resolvedDomain
	defaultRoute bool
	tls          string
}

func (m *recoveryResolver) GetLink(int32) (dbus.ObjectPath, *dbus.Error) {
	return "/org/freedesktop/resolve1/link/_77", nil
}
func (m *recoveryResolver) SetLinkDNS(_ int32, v []resolvedDNS) *dbus.Error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dns = v
	m.sets.Add(1)
	return nil
}
func (m *recoveryResolver) SetLinkDomains(_ int32, v []resolvedDomain) *dbus.Error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.domains = v
	return nil
}
func (m *recoveryResolver) SetLinkDefaultRoute(_ int32, v bool) *dbus.Error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultRoute = v
	return nil
}
func (m *recoveryResolver) SetLinkDNSOverTLS(_ int32, v string) *dbus.Error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tls = v
	return nil
}
func (m *recoveryResolver) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if iface == resolvedManager {
		if m.fail.Load() {
			return nil, dbus.NewError("org.freedesktop.DBus.Error.Failed", nil)
		}
		return map[string]dbus.Variant{"DNSEx": dbus.MakeVariant([]networkDNSServer{}), "Domains": dbus.MakeVariant([]networkDNSDomain{}), "DNSOverTLS": dbus.MakeVariant("no")}, nil
	}
	m.checks.Add(1)
	return map[string]dbus.Variant{"DNS": dbus.MakeVariant(m.dns), "Domains": dbus.MakeVariant(m.domains), "DefaultRoute": dbus.MakeVariant(m.defaultRoute), "DNSOverTLS": dbus.MakeVariant(m.tls)}, nil
}

func TestResolvedRecoverySurvivesInventoryResolverAndBusLoss(t *testing.T) {
	for _, native := range []bool{true, false} {
		name := "network"
		if !native {
			name = "explicit"
		}
		t.Run(name, func(t *testing.T) { testResolvedRecovery(t, native) })
	}
}
func testResolvedRecovery(t *testing.T, native bool) {
	if os.Getenv("AMNEZIA_RESOLVED_RECOVERY_TEST") != "1" {
		t.Skip("opt-in private D-Bus integration")
	}
	executable, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	address := "unix:path=" + filepath.Join(t.TempDir(), "bus")
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", address)
	startBus := func() func() {
		cmd := exec.CommandContext(ctx, executable, "--session", "--nofork", "--address="+address, "--print-address=1")
		out, e := cmd.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		scanner := bufio.NewScanner(out)
		if !scanner.Scan() {
			t.Fatal("private bus did not start")
		}
		var once sync.Once
		stop := func() {
			once.Do(func() {
				cmd.Process.Kill()
				cmd.Wait()
				os.Remove(address[len("unix:path="):])
			})
		}
		t.Cleanup(stop)
		return stop
	}
	startResolver := func() (*recoveryResolver, *dbus.Conn) {
		c, e := dbus.ConnectSystemBus(dbus.WithContext(ctx))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Close() })
		m := &recoveryResolver{}
		for _, row := range []struct {
			path  dbus.ObjectPath
			iface string
		}{{"/org/freedesktop/resolve1", resolvedManager}, {"/org/freedesktop/resolve1", "org.freedesktop.DBus.Properties"}, {"/org/freedesktop/resolve1/link/_77", "org.freedesktop.DBus.Properties"}} {
			if e = c.Export(m, row.path, row.iface); e != nil {
				t.Fatal(e)
			}
		}
		reply, e := c.RequestName(resolvedService, dbus.NameFlagDoNotQueue)
		if e != nil || reply != dbus.RequestNameReplyPrimaryOwner {
			t.Fatal("resolver could not own private name", e)
		}
		return m, c
	}
	wait := func(reason string, condition func() bool) {
		t.Helper()
		deadline := time.NewTimer(7 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if condition() {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-deadline.C:
				t.Fatal(reason)
			case <-ticker.C:
			}
		}
	}
	stopBus := startBus()
	first, service := startResolver()
	var frozen atomic.Bool
	var reloads atomic.Int32
	recovery := &networkDNSRecovery{nativeInventory: native, fingerprint: func() string {
		if native {
			return networkDNSFingerprint(nil)
		}
		return ""
	}(), suspend: func() { frozen.Store(true) }, reload: func(_ []networkDNSLink) error { reloads.Add(1); frozen.Store(false); return nil }}
	owner, e := startResolvedLinkWithRecovery(ctx, 77, "", recovery)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	alive := func() {
		t.Helper()
		select {
		case <-owner.done:
			t.Fatal("resolver outage terminated the live owner", owner.Err())
		default:
		}
	}
	wait("initial reconciliations did not run", func() bool { return first.checks.Load() >= 2 })
	if reloads.Load() != 0 {
		t.Fatal("startup watcher replaced the already valid DNS generation")
	}
	if native {
		first.fail.Store(true)
		wait("invalid inventory did not suspend DNS", frozen.Load)
		alive()
		first.fail.Store(false)
		wait("valid inventory did not resume DNS", func() bool { return !frozen.Load() && reloads.Load() > 0 })
		alive()
	}
	if _, e = service.ReleaseName(resolvedService); e != nil {
		t.Fatal(e)
	}
	second, _ := startResolver()
	wait("resolver restart did not restore only the managed link", func() bool { return second.sets.Load() > 0 })
	alive()
	stopBus()
	wait("system bus loss did not suspend DNS", frozen.Load)
	alive()
	startBus()
	third, _ := startResolver()
	wait("new bus/resolver did not recover the live owner", func() bool { return third.sets.Load() > 0 && !frozen.Load() })
	alive()
	if owner.Err() != nil {
		t.Fatal(errors.New("temporary outage became fatal"))
	}
}
