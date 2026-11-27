//go:build linux && !android

package nativedns

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Requires a caller-owned isolated namespace with dns-fixture assigned
// 192.0.2.10/32. It does not create or modify interfaces in the host namespace.
func TestSocketFrontendNativeLinkScope(t *testing.T) {
	if os.Getenv("AMNEZIA_DNS_LOCAL_INTERFACE_TEST") != "isolated-namespace" {
		t.Skip("requires an owned interface fixture")
	}
	native, err := net.InterfaceByName("dns-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if native.Flags&net.FlagUp == 0 || !assignedIPv4(net.ParseIP("192.0.2.10")) {
		t.Fatal("fixture does not own the native IPv4 address")
	}
	dialer := &net.Dialer{Timeout: time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		var bound error
		if err := raw.Control(func(fd uintptr) {
			bound = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, native.Name)
		}); err != nil {
			return err
		}
		return bound
	}}
	udp, err := net.ListenPacket("udp4", "192.0.2.10:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	f, err := NewSocket(context.Background(), udp, tcp, func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		return new(dns.Msg).SetReply(query), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, network := range []string{"udp", "tcp"} {
		answer, _, err := (&dns.Client{Net: network, Timeout: time.Second, Dialer: dialer}).Exchange(new(dns.Msg).SetQuestion("example.test.", dns.TypeAAAA), tcp.Addr().String())
		if err != nil || answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 {
			t.Fatal("native link-scoped resolver did not receive NODATA", network, answer, err)
		}
	}
	// Red control: replacing the original per-link scope with a plain loopback
	// listener does not work. Preserve this negative case, not a silent global
	// resolver substitution that merely makes resolution appear to succeed.
	loopUDP, loopTCP := socketPair(t)
	loop, err := NewSocket(context.Background(), loopUDP, loopTCP, func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		t.Error("link-scoped request escaped to loopback")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	if answer, _, err := (&dns.Client{Net: "udp", Timeout: 150 * time.Millisecond, Dialer: dialer}).Exchange(new(dns.Msg).SetQuestion("example.test.", dns.TypeAAAA), loopTCP.Addr().String()); err == nil {
		t.Fatal("negative per-link loopback control unexpectedly succeeded", answer)
	}
}

func TestNativeSessionPreparationAndIPv6FailClosed(t *testing.T) {
	if os.Getenv("AMNEZIA_DNS_LOCAL_INTERFACE_TEST") != "isolated-namespace" {
		t.Skip("requires caller-owned namespace and DNS port")
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	var forwarded atomic.Int32
	upstream := resolverServer(t, "udp", func(w dns.ResponseWriter, q *dns.Msg) {
		forwarded.Add(1)
		if q.Question[0].Qtype == dns.TypeAAAA {
			t.Error("AAAA escaped to original resolver")
		}
		_ = w.WriteMsg(new(dns.Msg).SetReply(q))
	})
	config := Config{Bindings: []Binding{
		{Endpoint: netip.MustParseAddrPort("192.0.2.10:53"), Upstream: upstream, InterfaceName: lo.Name, InterfaceIndex: lo.Index},
		{Endpoint: netip.MustParseAddrPort("127.0.0.1:53"), Upstream: netip.MustParseAddrPort("[2001:db8::53]:53"), InterfaceName: lo.Name, InterfaceIndex: lo.Index},
	}}
	session, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, binding := range config.Bindings {
		for _, network := range []string{"udp", "tcp"} {
			answer, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(new(dns.Msg).SetQuestion("example.test.", dns.TypeAAAA), binding.Endpoint.String())
			if err != nil || answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 {
				t.Fatal("local session NODATA failed", binding, network, answer, err)
			}
		}
		answer, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(new(dns.Msg).SetQuestion("example.test.", dns.TypeA), binding.Endpoint.String())
		want := dns.RcodeSuccess
		if binding.Upstream.Addr().Is6() {
			want = dns.RcodeServerFailure
		}
		if err != nil || answer.Rcode != want {
			t.Fatal("original resolver policy changed", binding, answer, err)
		}
	}
	before := forwarded.Load()
	session.Quiesce()
	for _, binding := range config.Bindings {
		for _, network := range []string{"udp", "tcp"} {
			for _, qtype := range []uint16{dns.TypeAAAA, dns.TypeA} {
				answer, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(
					new(dns.Msg).SetQuestion("quiesced.test.", qtype), binding.Endpoint.String())
				want := dns.RcodeSuccess
				if qtype == dns.TypeA {
					want = dns.RcodeServerFailure
				}
				if err != nil || answer == nil || answer.Rcode != want {
					t.Fatal("quiesced native endpoint lost fail-closed DNS", binding, network, answer, err)
				}
			}
		}
	}
	if forwarded.Load() != before {
		t.Fatal("session forwarded after quiesce")
	}
	_ = session.Close()
	// A failed later binding must join and retire all earlier prepared sockets.
	config.Bindings[1].Endpoint = netip.MustParseAddrPort("192.0.2.222:53")
	if failed, err := Start(context.Background(), config); err == nil {
		failed.Close()
		t.Fatal("unassigned later binding accepted")
	}
	listener, err := net.Listen("tcp4", "192.0.2.10:53")
	if err != nil {
		t.Fatal("failed transaction leaked native endpoint", err)
	}
	_ = listener.Close()
}
