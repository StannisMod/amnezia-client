package engine

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestPlatformPauseKeepsRoutedTCPAndOnlyRejectsNewCaptureFlows(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	var dialer net.Dialer
	var lc net.ListenConfig
	ctx := Context(context.Background(), Underlay{DialContext: dialer.DialContext, ListenPacket: lc.ListenPacket})
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
	raw, _ := json.Marshal(map[string]any{
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "unused", "server": "127.0.0.1"}}, "final": "unused"},
		"route":     map[string]any{"final": "vpn"},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "vpn"}},
	})
	runtime, err := StartRuntime(ctx, raw, "")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	open := func(inbound string) net.Conn {
		a, b := net.Pipe()
		a.SetDeadline(time.Now().Add(3 * time.Second))
		go runtime.box.Router().RouteConnectionEx(ctx, b, adapter.InboundContext{Inbound: inbound, Network: "tcp", Source: M.ParseSocksaddr("172.19.0.1:40001"), Destination: M.ParseSocksaddr(listener.Addr().String())}, nil)
		return a
	}
	exchange := func(c net.Conn) {
		t.Helper()
		data := []byte("same TCP while policy is paused")
		if _, err := c.Write(data); err != nil {
			t.Fatal(err)
		}
		answer := make([]byte, len(data))
		if _, err := io.ReadFull(c, answer); err != nil || string(answer) != string(data) {
			t.Fatalf("old TCP failed: %v", err)
		}
	}
	old := open(TUNTag)
	defer old.Close()
	exchange(old)
	if err = runtime.SetNewFlowsPaused(true); err != nil {
		t.Fatal(err)
	}
	if !runtime.Diagnostics().NewFlowsPaused {
		t.Fatal("pause not reported")
	}
	for _, network := range []string{"tcp", "udp"} {
		m := adapter.InboundContext{Inbound: TUNTag, Network: network, Source: M.ParseSocksaddr("172.19.0.1:40002"), Destination: M.ParseSocksaddr(listener.Addr().String())}
		if runtime.box.Router().PreMatch(m, nil).Action != adapter.PreMatchContinue {
			t.Fatalf("%s pause intercepted established packet processing", network)
		}
	}
	blocked := open(TUNTag)
	_, err = blocked.Write([]byte("must not dial"))
	blocked.Close()
	if err == nil {
		t.Fatal("new captured connection was accepted")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("paused flow stalled instead of rejecting")
	}
	exchange(old)
	if accepted.Load() != 1 {
		t.Fatal("pause redialed or leaked a new captured flow")
	}
	// Platform recovery is not itself captured application traffic.
	internal := open("platform-maintenance")
	exchange(internal)
	internal.Close()
	if err = runtime.SetNewFlowsPaused(false); err != nil {
		t.Fatal(err)
	}
	fresh := open(TUNTag)
	exchange(fresh)
	fresh.Close()
	exchange(old)
	if accepted.Load() != 3 || runtime.Diagnostics().NewFlowsPaused {
		t.Fatal("resume replaced old TCP or failed to restore new flows")
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if runtime.SetNewFlowsPaused(false) == nil {
		t.Fatal("stopped runtime accepted a policy update")
	}
}
