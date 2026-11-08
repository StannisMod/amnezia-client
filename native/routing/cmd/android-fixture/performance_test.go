//go:build !android && !ios

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

// These measurements use loopback and userspace peers. They isolate fixture,
// encryption/flow-stack and DNS-router costs; they do not represent a device's
// native TUN, Internet/VPS latency or an end-to-end product throughput claim.
func benchmarkPeer(b *testing.B, kind string) (context.Context, awg.Config) {
	b.Helper()
	oldKind, oldBulk := transportKind, bulkEnabled
	transportKind, bulkEnabled = kind, true
	b.Cleanup(func() { transportKind, bulkEnabled = oldKind, oldBulk })
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	f := &fixture{server: server, client: client}
	if err := f.start(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(f.stop)
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	cfg := awg.Config{
		Address:    []netip.Addr{netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("fd77::1")},
		PrivateKey: base64.StdEncoding.EncodeToString(client.Bytes()),
		PublicKey:  base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()),
		Endpoint:   netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), f.listenPort),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
	}
	if kind != "wireguard" {
		cfg.Parameters = map[string]string{"jc": "3", "jmin": "40", "jmax": "80", "s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}
	}
	return ctx, cfg
}

func benchmarkDialer(b *testing.B, kind string) func(context.Context, string, string) (net.Conn, error) {
	b.Helper()
	peerKind := kind
	if kind == "awg_buffered" {
		peerKind = "awg"
	}
	ctx, cfg := benchmarkPeer(b, peerKind)
	var lc net.ListenConfig
	listen := lc.ListenPacket
	if kind == "awg_buffered" {
		// Diagnostic A/B only: the pinned AWG default bind requests 7 MiB
		// socket buffers, while our protected packet bind currently does not.
		listen = func(ctx context.Context, network, address string) (net.PacketConn, error) {
			pc, err := lc.ListenPacket(ctx, network, address)
			if err == nil {
				udp := pc.(*net.UDPConn)
				_ = udp.SetReadBuffer(7 << 20)
				_ = udp.SetWriteBuffer(7 << 20)
			}
			return pc, err
		}
	}
	transport, err := awg.New(ctx, cfg, listen)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { transport.Close() })
	return transport.DialContext
}

func BenchmarkTunnelBulk(b *testing.B) {
	for _, kind := range []string{"native_tcp", "wireguard", "awg", "awg_buffered"} {
		b.Run(kind, func(b *testing.B) {
			var dial func(context.Context, string, string) (net.Conn, error)
			address := "10.77.0.2:18444"
			if kind == "native_tcp" {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { listener.Close() })
				var accepted atomic.Int64
				go observeBulk(listener, "VPN", &accepted)
				address = listener.Addr().String()
				var d net.Dialer
				dial = d.DialContext
			} else {
				dial = benchmarkDialer(b, kind)
			}
			const size = 1 << 20
			data, expected := make([]byte, size), bytes.Repeat([]byte{'Z'}, size)
			var payloadTime, eofTime time.Duration
			b.SetBytes(size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c, err := dial(context.Background(), "tcp", address)
				if err != nil {
					b.Fatal(err)
				}
				c.SetDeadline(time.Now().Add(120 * time.Second))
				if err = binary.Write(c, binary.BigEndian, uint32(size)); err != nil {
					c.Close()
					b.Fatal(err)
				}
				r := bufio.NewReader(c)
				label, err := r.ReadString('\n')
				if err != nil || label != "VPN\n" {
					c.Close()
					b.Fatalf("observer %q: %v", label, err)
				}
				began := time.Now()
				_, err = io.ReadFull(r, data)
				payloadTime += time.Since(began)
				if err != nil || !bytes.Equal(data, expected) {
					c.Close()
					b.Fatalf("payload: %v", err)
				}
				began = time.Now()
				_, err = r.ReadByte()
				eofTime += time.Since(began)
				c.Close()
				if err != io.EOF {
					b.Fatalf("expected EOF after exact payload: %v", err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(payloadTime.Nanoseconds())/float64(b.N), "payload-ns/op")
			b.ReportMetric(float64(eofTime.Nanoseconds())/float64(b.N), "eof-ns/op")
		})
	}
}

func BenchmarkTunnelDNS(b *testing.B) {
	for _, kind := range []string{"native_udp", "awg_udp", "router_vpn_cold", "router_vpn_cached"} {
		b.Run(kind, func(b *testing.B) {
			var exchange func(*dns.Msg) (*dns.Msg, error)
			if kind == "native_udp" {
				pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					b.Fatal(err)
				}
				server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
					a := new(dns.Msg)
					a.SetReply(q)
					a.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP(sharedIP)}}
					w.WriteMsg(a)
				})}
				go server.ActivateAndServe()
				b.Cleanup(func() { server.Shutdown(); pc.Close() })
				exchange = func(q *dns.Msg) (*dns.Msg, error) {
					a, _, e := (&dns.Client{Timeout: 5 * time.Second}).Exchange(q, pc.LocalAddr().String())
					return a, e
				}
			} else if kind == "awg_udp" {
				dial := benchmarkDialer(b, "awg")
				exchange = func(q *dns.Msg) (*dns.Msg, error) {
					c, e := dial(context.Background(), "udp", "10.77.0.2:53")
					if e != nil {
						return nil, e
					}
					defer c.Close()
					a, _, e := (&dns.Client{Timeout: 5 * time.Second}).ExchangeWithConn(q, &dns.Conn{Conn: c})
					return a, e
				}
			} else {
				ctx, cfg := benchmarkPeer(b, "awg")
				raw, err := (engine.SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN}, Resolver: netip.MustParseAddrPort("10.77.0.2:53"), ResolverAction: rules.VPN, AWG: cfg}).Compile()
				if err != nil {
					b.Fatal(err)
				}
				var options map[string]any
				if err := json.Unmarshal(raw, &options); err != nil {
					b.Fatal(err)
				}
				options["inbounds"] = []any{}
				raw, err = json.Marshal(options)
				if err != nil {
					b.Fatal(err)
				}
				var lc net.ListenConfig
				var d net.Dialer
				ctx = engine.Context(ctx, engine.Underlay{ListenPacket: lc.ListenPacket, DialContext: d.DialContext})
				ctx = service.ContextWith[adapter.PlatformInterface](ctx, fixturePlatform{})
				box, err := engine.New(ctx, raw)
				if err != nil {
					b.Fatal(err)
				}
				if err := box.Start(); err != nil {
					box.Close()
					b.Fatal(err)
				}
				b.Cleanup(func() { box.Close() })
				dr := service.FromContext[adapter.DNSRouter](ctx)
				upstream, ok := service.FromContext[adapter.DNSTransportManager](ctx).Transport("upstream")
				if !ok {
					b.Fatal("missing upstream")
				}
				exchange = func(q *dns.Msg) (*dns.Msg, error) {
					return dr.Exchange(ctx, q, adapter.DNSQueryOptions{Transport: upstream})
				}
			}
			// Warm the handshake; cold means DNS-cache miss, not VPN startup.
			q := new(dns.Msg)
			q.SetQuestion("warm.test.", dns.TypeA)
			if _, err := exchange(q); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				name := fmt.Sprintf("query%d.test.", i)
				if kind == "router_vpn_cached" {
					name = "warm.test."
				}
				q := new(dns.Msg)
				q.SetQuestion(name, dns.TypeA)
				a, err := exchange(q)
				if err != nil {
					b.Fatal(err)
				}
				if len(a.Answer) != 1 {
					b.Fatal("missing DNS answer")
				}
				answer, ok := a.Answer[0].(*dns.A)
				if !ok || !answer.A.Equal(net.ParseIP(sharedIP)) {
					b.Fatal("wrong DNS observer")
				}
			}
		})
	}
}
