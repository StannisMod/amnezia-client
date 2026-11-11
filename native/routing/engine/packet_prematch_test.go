package engine

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// Exercise the pinned router's actual PreMatch switch, not just our predicate.
// A following unconditional reject makes accidental fall-through observable.
// Complete routing must still see that reject; this guard only defers the
// synchronous packet-reader pass to the connection's asynchronous handler.
func TestPacketPreMatchDefersWithoutBypassingPolicy(t *testing.T) {
	ctx := Context(context.Background(), Underlay{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unexpected dial") }, ListenPacket: func(context.Context, string, string) (net.PacketConn, error) {
		return nil, errors.New("unexpected packet socket")
	}})
	instance, err := New(ctx, []byte(`{"route":{"rules":[{"action":"reject"}]},"outbounds":[{"type":"direct","tag":"direct"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	for _, network := range []string{"tcp", "udp"} {
		m := adapter.InboundContext{Inbound: TUNTag, Network: network, Source: M.ParseSocksaddr("172.19.0.1:40000"), Destination: M.ParseSocksaddr("198.18.0.2:123")}
		got := instance.Router().PreMatch(m, []byte{0, 1, 2, 3})
		if got.Action != adapter.PreMatchContinue {
			t.Fatalf("%s: packet reader evaluated policy: %v", network, got.Action)
		}
		parsed := instance.Router().Rules()
		if parsed[0].Match(&m) {
			t.Fatal("guard intercepted normal routing")
		}
		if !parsed[1].Match(&m) || parsed[1].Action().Type() != "reject" {
			t.Fatal("normal rejection policy lost")
		}
	}
	for _, m := range []adapter.InboundContext{
		{Inbound: TUNTag, Network: "icmp"}, {Inbound: "another-inbound", Network: "udp"},
	} {
		m.PreMatch = true
		if instance.Router().Rules()[0].Match(&m) {
			t.Fatal("guard intercepted unsupported flow")
		}
	}
}
