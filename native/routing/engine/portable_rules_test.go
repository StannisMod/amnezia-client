package engine

import (
	"context"
	stdjson "encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	SBuf "github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// The Qt editor checker and the actual pinned matcher share this corpus.
func TestPortablePoliciesAgainstSingBox(t *testing.T) {
	data, err := os.ReadFile("../rules/testdata/portable-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name    string
		Invalid bool
		Config  stdjson.RawMessage
		Probes  []struct {
			Domain, IP, Network string
			Port                uint16
			Action              string
		}
	}
	if err = stdjson.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if tc.Invalid {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			var cfg rules.Config
			if err := stdjson.Unmarshal(tc.Config, &cfg); err != nil {
				t.Fatal(err)
			}
			raw, err := cfg.Compile()
			if err != nil {
				t.Fatal(err)
			}
			var options option.RouteOptions
			if err := json.UnmarshalContext(context.Background(), raw, &options); err != nil {
				t.Fatal(err)
			}
			var parsed []adapter.Rule
			for _, o := range options.Rules {
				r, err := R.NewRule(context.Background(), log.NewNOPFactory().NewLogger("test"), o, true)
				if err != nil {
					t.Fatal(err)
				}
				parsed = append(parsed, r)
			}
			for _, q := range tc.Probes {
				domain, _ := rules.NormalizeDomain(q.Domain)
				ip, _ := netip.ParseAddr(q.IP)
				m := adapter.InboundContext{Domain: domain, Network: q.Network, Destination: M.Socksaddr{Addr: ip, Port: q.Port}}
				got := options.Final
				for _, r := range parsed {
					m.ResetRuleCache()
					if !r.Match(&m) {
						continue
					}
					if r.Action().Type() == "reject" {
						got = "block"
					} else {
						got = r.Action().(*R.RuleActionRoute).Outbound
					}
					break
				}
				if got != q.Action {
					t.Fatalf("%+v: actual sing-box chose %s", q, got)
				}
			}
		})
	}
}

func TestBlockNeverOpensUnderlay(t *testing.T) {
	for _, defaultBlock := range []bool{false, true} {
		t.Run(map[bool]string{false: "rule", true: "default"}[defaultBlock], func(t *testing.T) {
			policy := rules.Config{Version: 2, Default: rules.VPN, Rules: []rules.Rule{{Kind: rules.Domain, Value: "blocked.test", Action: rules.Block, Ports: "443-444"}}}
			if defaultBlock {
				policy.Default = rules.Block
				policy.Rules = nil
			}
			raw, err := (RoutingConfig{Rules: policy, Resolver: netip.MustParseAddrPort("127.0.0.1:53"), ResolverAction: rules.Direct}).compile(map[string]any{"type": "direct", "tag": "vpn"})
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			if err := stdjson.Unmarshal(raw, &config); err != nil {
				t.Fatal(err)
			}
			delete(config, "inbounds")
			raw, _ = stdjson.Marshal(config)
			var calls atomic.Int32
			ctx := Context(context.Background(), Underlay{
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					calls.Add(1)
					return nil, errors.New("unexpected outbound dial")
				},
				ListenPacket: func(context.Context, string, string) (net.PacketConn, error) {
					calls.Add(1)
					return nil, errors.New("unexpected outbound packet socket")
				},
			})
			ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
			instance, err := New(ctx, raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			for _, network := range []string{"tcp", "udp"} {
				app, capture := net.Pipe()
				done := make(chan error, 1)
				metadata := adapter.InboundContext{Inbound: TUNTag, Network: network, Domain: "blocked.test", Destination: M.ParseSocksaddr("127.0.0.1:443")}
				if network == "tcp" {
					go instance.Router().RouteConnectionEx(ctx, capture, metadata, func(err error) { done <- err })
				} else {
					go instance.Router().RoutePacketConnectionEx(ctx, SBuf.NewUnbindPacketConnWithAddr(capture, metadata.Destination), metadata, func(err error) { done <- err })
				}
				select {
				case err := <-done:
					if err == nil {
						t.Error("Block returned success", network)
					}
				case <-time.After(2 * time.Second):
					t.Error("Block did not finish", network)
				}
				app.Close()
			}
			if calls.Load() != 0 {
				t.Fatal("blocked traffic reached underlay", calls.Load())
			}
		})
	}
}
