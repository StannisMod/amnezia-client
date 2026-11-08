//go:build linux && !android

package desktop

import (
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestNativeNetworkEpochSeesUnrelatedRoutesButExcludesCapture(t *testing.T) {
	if os.Getenv("AMNEZIA_NETWORK_EPOCH_TEST") != "1" {
		t.Skip("requires isolated native network fixture")
	}
	switch os.Getenv("AMNEZIA_STABILITY_LAB") {
	case "isolated-container":
		group, e := os.ReadFile("/proc/self/cgroup")
		if e != nil || strings.TrimSpace(string(group)) != "0::/" {
			t.Fatal("refusing outside private cgroup namespace")
		}
		procs, e := os.ReadFile("/sys/fs/cgroup/cgroup.procs")
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, pid := range strings.Fields(string(procs)) {
			if pid == strconv.Itoa(os.Getpid()) {
				found = true
			}
		}
		if !found {
			t.Fatal("refusing outside this container cgroup")
		}
	case "isolated-namespace":
		own, e := os.Stat("/proc/self/ns/net")
		if e != nil {
			t.Fatal(e)
		}
		initial, e := os.Stat("/proc/1/ns/net")
		if e != nil || os.SameFile(own, initial) {
			t.Fatal("refusing native route test in initial network namespace")
		}
	default:
		t.Fatal("isolated native wrapper required")
	}
	run := func(args ...string) {
		t.Helper()
		if b, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			t.Fatalf("ip %v: %v %s", args, e, b)
		}
	}
	epoch := func() string {
		t.Helper()
		value, e := nativeNetworkEpoch()
		if e != nil {
			t.Fatal(e)
		}
		return value
	}
	run("link", "add", "epoch-native0", "type", "dummy")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "epoch-native0").Run() })
	run("link", "set", "epoch-native0", "up")
	run("addr", "add", "192.0.2.1/24", "dev", "epoch-native0")
	run("route", "add", "198.51.100.0/24", "via", "192.0.2.2", "dev", "epoch-native0", "table", "1000", "metric", "10")
	before := epoch()
	endpoint := netip.MustParseAddrPort("127.0.0.1:51820")
	protected, e := protectedRouteFingerprint(endpoint)
	if e != nil {
		t.Fatal(e)
	}
	run("route", "replace", "198.51.100.0/24", "via", "192.0.2.3", "dev", "epoch-native0", "table", "1000", "metric", "10")
	changed := epoch()
	same, e := protectedRouteFingerprint(endpoint)
	if e != nil || same != protected || changed == before {
		t.Fatal("unrelated physical gateway change was missed", e)
	}
	run("rule", "add", "priority", "1000", "fwmark", "0x100", "table", "1000")
	t.Cleanup(func() {
		exec.Command("ip", "rule", "del", "priority", "1000", "fwmark", "0x100", "table", "1000").Run()
	})
	policy := epoch()
	if policy == changed {
		t.Fatal("native mark policy change was missed")
	}
	run("link", "add", InterfaceName, "type", "dummy")
	t.Cleanup(func() { exec.Command("ip", "link", "del", InterfaceName).Run() })
	run("link", "set", InterfaceName, "up")
	run("addr", "add", "172.19.0.1/30", "dev", InterfaceName)
	run("route", "add", "default", "dev", InterfaceName, "table", "20313")
	run("rule", "add", "priority", "1", "fwmark", "0x20000000/0x20000000", "table", "20313")
	t.Cleanup(func() {
		exec.Command("ip", "rule", "del", "priority", "1", "fwmark", "0x20000000/0x20000000", "table", "20313").Run()
	})
	if epoch() != policy {
		t.Fatal("owned capture triggered a DNS invalidation loop")
	}
	if epoch() != policy {
		t.Fatal("unchanged native inventory produced an unstable epoch")
	}
}
