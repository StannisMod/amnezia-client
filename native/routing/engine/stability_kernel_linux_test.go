//go:build linux && !android

package engine

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
)

// This opt-in path is only permitted inside the disposable lab container.
// The independent kernel TCP peer lives in its own network namespace.
func stabilityKernelPeer(t *testing.T, config awg.Config) (netip.AddrPort, net.Listener) {
	t.Helper()
	if mode := os.Getenv("AMNEZIA_STABILITY_LAB"); mode != "isolated-container" && mode != "isolated-namespace" {
		t.Fatal("kernel peer requires the isolated lab wrapper")
	}
	command := func(args ...string) {
		t.Helper()
		if b, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			t.Fatalf("ip %v: %v %s", args, e, b)
		}
	}
	command("netns", "add", "stability-peer")
	t.Cleanup(func() { exec.Command("ip", "netns", "del", "stability-peer").Run() })
	command("link", "add", "stb-underlay", "type", "veth", "peer", "name", "eth0", "netns", "stability-peer")
	// Deleting the named namespace alone is insufficient while kernel socket
	// references are still draining. Remove only this fixture's owned pair.
	t.Cleanup(func() { exec.Command("ip", "link", "del", "stb-underlay").Run() })
	command("addr", "add", "203.0.113.1/24", "dev", "stb-underlay")
	command("link", "set", "stb-underlay", "up")
	command("-n", "stability-peer", "link", "set", "lo", "up")
	command("-n", "stability-peer", "addr", "add", "203.0.113.2/24", "dev", "eth0")
	command("-n", "stability-peer", "link", "set", "eth0", "up")
	command("route", "add", "default", "via", "203.0.113.2", "dev", "stb-underlay")
	var listener net.Listener
	var endpoint netip.AddrPort
	withStabilityNS(t, "/run/netns/stability-peer", func() error {
		packet, e := tun.CreateTUN("stb-peer", 1280)
		if e != nil {
			return e
		}
		key := func(v string) string { b, _ := base64.StdEncoding.DecodeString(v); return hex.EncodeToString(b) }
		ipc := fmt.Sprintf("private_key=%s\nlisten_port=0\n", key(config.PrivateKey))
		for k, v := range config.Parameters {
			ipc += k + "=" + v + "\n"
		}
		ipc += fmt.Sprintf("replace_peers=true\npublic_key=%s\nallowed_ip=%s\n", key(config.PublicKey), config.AllowedIPs[0])
		device, e := awg.NewConfiguredDevice(packet, conn.NewStdNetBind(), ipc)
		if e != nil {
			return e
		}
		t.Cleanup(device.Close)
		state, e := device.IpcGet()
		if e != nil {
			return e
		}
		var port int
		for _, line := range strings.Split(state, "\n") {
			if strings.HasPrefix(line, "listen_port=") {
				fmt.Sscanf(line, "listen_port=%d", &port)
			}
		}
		endpoint = netip.AddrPortFrom(netip.MustParseAddr("203.0.113.2"), uint16(port))
		address := config.Address[0]
		prefix := "/32"
		if address.Is6() {
			prefix = "/128"
		}
		// These commands inherit this locked OS thread's namespace.
		command("addr", "add", address.String()+prefix, "dev", "stb-peer", "nodad")
		command("link", "set", "stb-peer", "up")
		if address.Is6() {
			command("-6", "route", "add", config.AllowedIPs[0].String(), "dev", "stb-peer")
		} else {
			command("route", "add", config.AllowedIPs[0].String(), "dev", "stb-peer")
		}
		listener, e = net.Listen("tcp", net.JoinHostPort(address.String(), "18443"))
		if e == nil && os.Getenv("AMNEZIA_STABILITY_DOMAIN_MOVE") == "1" {
			endpoint = stabilityDomainFrontdoors(t, endpoint)
		}
		return e
	})
	if os.Getenv("AMNEZIA_STABILITY_DOMAIN_MOVE") == "1" {
		command("route", "add", "1.1.1.1/32", "via", "203.0.113.2", "dev", "stb-underlay")
	}
	// Capture only headers on the synthetic peer interface. TLS contents/keys are
	// never recorded. ss exposes kernel retransmission/window/timer diagnostics.
	if directory := os.Getenv("AMNEZIA_STABILITY_TRACE"); directory != "" {
		if e := os.MkdirAll(directory, 0755); e != nil {
			t.Fatal(e)
		}
		prefix := strings.NewReplacer("/", "_", "[", "", "]", "", " ", "_").Replace(t.Name())
		trace, e := os.Create(filepath.Join(directory, prefix+".tcp.txt"))
		if e != nil {
			t.Fatal(e)
		}
		capture := exec.Command("ip", "netns", "exec", "stability-peer", "tcpdump", "-i", "stb-peer", "-n", "-tt", "-S", "-l", "tcp", "port", "18443")
		capture.Stdout = trace
		capture.Stderr = trace
		if e = capture.Start(); e != nil {
			t.Fatal(e)
		}
		stop := make(chan struct{})
		done := make(chan struct{})
		stats, e := os.Create(filepath.Join(directory, prefix+".ss.txt"))
		if e != nil {
			t.Fatal(e)
		}
		go func() {
			defer close(done)
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case at := <-tick.C:
					fmt.Fprintln(stats, at.Format(time.RFC3339Nano))
					b, _ := exec.Command("ip", "netns", "exec", "stability-peer", "ss", "-tinop", "sport", "=", ":18443").CombinedOutput()
					stats.Write(b)
				}
			}
		}()
		t.Cleanup(func() {
			close(stop)
			<-done
			stats.Close()
			capture.Process.Signal(syscall.SIGINT)
			capture.Wait()
			trace.Close()
		})
	}
	return endpoint, listener
}
func withStabilityNS(t *testing.T, path string, fn func() error) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, e := os.Open("/proc/self/task/" + fmt.Sprint(unix.Gettid()) + "/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	defer original.Close()
	target, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	if e = unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); e != nil {
		t.Fatal(e)
	}
	result := fn()
	if e = unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); e != nil {
		panic(e)
	}
	if result != nil {
		t.Fatal(result)
	}
}

// Launch the unchanged desktop helper: real OS capture, production nft/routing
// ownership and protected sockets. Only system DNS management is disabled.
func stabilityStartNative(t *testing.T, profile []byte) (func() error, func() error) {
	t.Helper()
	helper := os.Getenv("AMNEZIA_STABILITY_HELPER")
	command := exec.Command(helper, "--no-system-dns", "--cache-dir", t.TempDir())
	input, e := command.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := command.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if e = command.Start(); e != nil {
		t.Fatal(e)
	}
	ready := make(chan error, 1)
	type acknowledgement struct {
		ID uint64 `json:"request_id"`
		OK bool   `json:"ok"`
	}
	acks := make(chan acknowledgement, 4)
	var pathChanges, probes, reopens, endpointChanges atomic.Uint64
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(output)
		sent := false
		for scanner.Scan() {
			var row struct {
				Type     string            `json:"type"`
				Message  string            `json:"message"`
				Recovery map[string]uint64 `json:"underlay_recovery"`
				acknowledgement
			}
			if json.Unmarshal(scanner.Bytes(), &row) != nil {
				continue
			}
			if row.Type == "status" {
				pathChanges.Store(row.Recovery["path_changes"])
				endpointChanges.Store(row.Recovery["endpoint_changes"])
				probes.Store(row.Recovery["probes"])
				if row.Recovery["reopens"] != reopens.Load() {
					t.Logf("native owner reopen attempt %d", row.Recovery["reopens"])
				}
				reopens.Store(row.Recovery["reopens"])
			}
			if !sent && row.Type == "ready" {
				ready <- nil
				sent = true
			}
			if row.Type == "error" {
				if !sent {
					ready <- fmt.Errorf("%s", row.Message)
					sent = true
				}
				t.Logf("native helper error: %s", row.Message)
			}
			if row.Type == "underlay_refreshed" {
				select {
				case acks <- row.acknowledgement:
				default:
				}
			}
		}
		if !sent {
			ready <- fmt.Errorf("helper exited before ready")
		}
	}()
	if _, e = input.Write(append(profile, '\n')); e != nil {
		t.Fatal(e)
	}
	var once sync.Once
	var inputMu sync.Mutex
	var requestID uint64
	var stopped error
	stop := func() error {
		once.Do(func() {
			inputMu.Lock()
			input.Write([]byte("stop\n"))
			input.Close()
			inputMu.Unlock()
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			select {
			case stopped = <-done:
			case <-time.After(15 * time.Second):
				command.Process.Kill()
				stopped = <-done
			}
			<-scanned
		})
		return stopped
	}
	t.Cleanup(func() { stop() })
	select {
	case e = <-ready:
		if e != nil {
			stop()
			t.Fatalf("%v %s", e, stderr.String())
		}
	case <-time.After(15 * time.Second):
		stop()
		t.Fatalf("native helper ready timeout: %s", stderr.String())
	}
	t.Logf("native helper ready pid=%d; real amnrouting0 capture", command.Process.Pid)
	var lastAutoChanges uint64
	refresh := func() error {
		if os.Getenv("AMNEZIA_STABILITY_AUTOMATIC") == "1" {
			budget := 8 * time.Second
			if os.Getenv("AMNEZIA_STABILITY_DOMAIN_MOVE") == "1" {
				budget = 45 * time.Second
			}
			deadline := time.NewTimer(budget)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				if os.Getenv("AMNEZIA_STABILITY_DOMAIN_MOVE") == "1" {
					if endpointChanges.Load() > 0 {
						t.Log("native owner moved the same peer to a fresh DNS answer without a manual refresh")
						return nil
					}
					select {
					case <-deadline.C:
						return fmt.Errorf("native owner did not rotate the failed domain endpoint")
					case <-tick.C:
					}
					continue
				}
				if pathChanges.Load() > lastAutoChanges && probes.Load() > 0 {
					lastAutoChanges = pathChanges.Load()
					if reopens.Load() != 0 {
						return fmt.Errorf("working authenticated socket was unnecessarily reopened")
					}
					t.Log("native owner detected the changed protected route; authenticated UDP remains open")
					return nil
				}
				select {
				case <-deadline.C:
					return fmt.Errorf("native owner did not observe/probe changed protected route")
				case <-tick.C:
				}
			}
		}
		inputMu.Lock()
		defer inputMu.Unlock()
		requestID++
		line, _ := json.Marshal(map[string]any{"type": "refresh_underlay", "request_id": requestID})
		if _, err := input.Write(append(line, '\n')); err != nil {
			return err
		}
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case ack := <-acks:
				if ack.ID != requestID {
					continue
				}
				if !ack.OK {
					return fmt.Errorf("native underlay refresh failed")
				}
				return nil
			case <-scanned:
				return fmt.Errorf("native owner exited during refresh")
			case <-timer.C:
				return fmt.Errorf("native underlay refresh acknowledgement timed out")
			}
		}
	}
	return stop, refresh
}
func stabilityNativeBlackhole(t *testing.T, enabled bool, endpoint netip.AddrPort) uint64 {
	t.Helper()
	run := func(name string, args ...string) []byte {
		b, e := exec.Command(name, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v %s", name, args, e, b)
		}
		return b
	}
	if enabled {
		rules := fmt.Sprintf("add table inet stability_loss\nadd chain inet stability_loss output { type filter hook output priority 0; policy accept; }\nadd chain inet stability_loss input { type filter hook input priority 0; policy accept; }\nadd rule inet stability_loss output ip daddr %s udp dport %d counter drop\nadd rule inet stability_loss input ip saddr %s udp sport %d counter drop\n", endpoint.Addr(), endpoint.Port(), endpoint.Addr(), endpoint.Port())
		c := exec.Command("nft", "-f", "-")
		c.Stdin = strings.NewReader(rules)
		if b, e := c.CombinedOutput(); e != nil {
			t.Fatalf("blackhole: %v %s", e, b)
		}
		return 0
	}
	raw := run("nft", "-j", "list", "table", "inet", "stability_loss")
	var decoded any
	json.Unmarshal(raw, &decoded)
	var count uint64
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if counter, ok := x["counter"].(map[string]any); ok {
				if n, ok := counter["packets"].(float64); ok {
					count += uint64(n)
				}
			}
			for _, v := range x {
				walk(v)
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		}
	}
	walk(decoded)
	run("nft", "delete", "table", "inet", "stability_loss")
	return count
}
func stabilityNativeImpairment(t *testing.T, enabled bool) {
	t.Helper()
	for _, prefix := range [][]string{nil, {"netns", "exec", "stability-peer"}} {
		dev := "stb-underlay"
		if len(prefix) > 0 {
			dev = "eth0"
		}
		if os.Getenv("AMNEZIA_STABILITY_INTERFACE_MOVE") == "1" {
			dev = "stb-alt"
			if len(prefix) > 0 {
				dev = "eth1"
			}
		}
		args := []string{"qdisc", "del", "dev", dev, "root"}
		if enabled {
			args = []string{"qdisc", "replace", "dev", dev, "root", "netem", "loss", "10%", "delay", "10ms", "5ms"}
			switch os.Getenv("AMNEZIA_STABILITY_PROFILE") {
			case "slow":
				args = []string{"qdisc", "replace", "dev", dev, "root", "netem", "limit", "256", "delay", "100ms", "50ms", "rate", "1mbit"}
			case "reorder":
				args = []string{"qdisc", "replace", "dev", dev, "root", "netem", "limit", "256", "delay", "40ms", "10ms", "reorder", "25%", "50%"}
			}
		}
		name := "tc"
		if len(prefix) > 0 {
			name = "ip"
			args = append(append(prefix, "tc"), args...)
		}
		if b, e := exec.Command(name, args...).CombinedOutput(); e != nil {
			t.Fatalf("netem: %v %s", e, b)
		}
	}
}
