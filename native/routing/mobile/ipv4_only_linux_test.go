//go:build linux && with_gvisor

package mobile

import (
	"context"
	"encoding/json"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	boxjson "github.com/sagernet/sing/common/json"
	"golang.org/x/sys/unix"
	"sync/atomic"
	"testing"
	"time"
)

func TestIPv4OnlySessionDoesNotAdvertiseUnusableFakeIPv6(t *testing.T) {
	var config engine.SessionConfig
	if err := json.Unmarshal(sampleConfig(t), &config); err != nil {
		t.Fatal(err)
	}
	config.DisableIPv6 = true
	compiled, err := config.Compile()
	if err != nil {
		t.Fatal(err)
	}
	var options map[string]any
	json.Unmarshal(compiled, &options)
	first := options["dns"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if first["action"] != "predefined" || first["rcode"] != "NOERROR" {
		t.Fatalf("missing empty AAAA response: %v", first)
	}
	// Parse actual pinned engine options, including the predefined DNS action.
	var parsed option.Options
	if err = boxjson.UnmarshalContext(engine.Context(context.Background(), engine.Underlay{}), compiled, &parsed); err != nil {
		t.Fatal(err)
	}
}

func TestIPv4OnlyNativeCaptureAnswersAAAAWithoutFakeDestination(t *testing.T) {
	for _, transport := range []string{"awg", "wireguard"} {
		t.Run(transport, func(t *testing.T) { testOwnedPacketFDManagedDNSAndCleanup(t, transport, true, true) })
	}
}

func TestUnexpectedPacketReaderExitIsReported(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[1])
	var released atomic.Int32
	platform, err := New(pair[0], Hooks{Protect: func(int) error { return nil }, Release: func() { released.Add(1) }, Interfaces: func() ([]adapter.NetworkInterface, error) { return nil, nil }})
	if err != nil {
		unix.Close(pair[0])
		t.Fatal(err)
	}
	session, err := StartWithNetworkDNS(context.Background(), platform, sampleConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err = session.Stats(); err != nil {
		t.Fatal(err)
	}
	if err = platform.capture.(*packetDescriptor).file.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err = session.Stats(); err != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err == nil {
		t.Fatalf("dead packet capture still reported healthy: capture=%T", platform.capture)
	}
	if released.Load() != 0 {
		t.Fatal("reader failure released JNI host before explicit close")
	}
	session.Close()
	if released.Load() != 1 {
		t.Fatal("host not released exactly once")
	}
}
