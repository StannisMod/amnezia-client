package engine

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func stabilityChaosSeconds(name string, fallback int) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return time.Duration(fallback) * time.Second
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 600 {
		panic("invalid bounded chaos duration: " + name)
	}
	return time.Duration(n) * time.Second
}

// Faults act on encrypted UDP outside the real Linux TUN. Application sockets
// are opened by reproduceStability once; this hook cannot dial replacements.
func stabilityNativeChaos(t *testing.T, progress func(), pauseWS func(bool)) {
	t.Helper()
	profile := os.Getenv("AMNEZIA_CHAOS_PROFILE")
	if profile == "" {
		return
	}
	if os.Getenv("AMNEZIA_STABILITY_LAB") != "isolated-namespace" || os.Getenv("AMNEZIA_STABILITY_HELPER") == "" {
		t.Fatal("chaos requires the disposable namespace wrapper and production helper")
	}
	script := os.Getenv("AMNEZIA_CHAOS_SCRIPT")
	if script == "" {
		t.Fatal("chaos fault driver missing")
	}
	identities := func() map[string]string {
		values := map[string]string{}
		entries, err := os.ReadDir("/proc")
		if err != nil {
			t.Fatal(err)
		}
		helper, _ := filepath.Abs(os.Getenv("AMNEZIA_STABILITY_HELPER"))
		for _, entry := range entries {
			executable, _ := os.Readlink("/proc/" + entry.Name() + "/exe")
			if executable != helper {
				continue
			}
			raw, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
			if err != nil {
				t.Fatal(err)
			}
			fields := strings.Fields(string(raw)[strings.LastIndex(string(raw), ")")+1:])
			if len(fields) < 20 {
				t.Fatal("invalid proc stat")
			}
			values[entry.Name()] = fields[19]
		}
		if len(values) != 1 {
			t.Fatalf("expected one live native helper, got %v", values)
		}
		return values
	}
	owner := identities()
	before, err := net.InterfaceByName("amnrouting0")
	if err != nil {
		t.Fatal(err)
	}
	command := func(action string) {
		t.Helper()
		cmd := exec.Command("python3", script, action, profile)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fault %s: %v %s", action, err, b)
		}
	}
	duration := stabilityChaosSeconds("AMNEZIA_CHAOS_SECONDS", 3)
	idle := os.Getenv("AMNEZIA_CHAOS_IDLE") == "1"
	if idle {
		pauseWS(true)
	}
	// Register rollback before apply: even partially applied faults are removed.
	defer command("clear")
	command("apply")
	time.Sleep(duration)
	command("witness")
	if os.Getenv("AMNEZIA_CHAOS_PROGRESS_DURING") == "1" {
		progress()
	}
	command("clear")
	pauseWS(false)
	restored := time.Now()
	progress()
	after, err := net.InterfaceByName("amnrouting0")
	if err != nil || before.Index != after.Index {
		t.Fatalf("TUN replaced: before=%v after=%v err=%v", before, after, err)
	}
	if !reflect.DeepEqual(owner, identities()) {
		t.Fatal("native helper restarted during fault")
	}
	row, _ := json.Marshal(map[string]any{"profile": profile, "fault_ms": duration.Milliseconds(), "resume_ms": time.Since(restored).Milliseconds(), "same_tun": true, "same_helper_process": true, "idle_websocket": idle})
	t.Logf("CHAOS_RESULT %s", row)
}
