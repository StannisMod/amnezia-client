//go:build linux && !android

package dnsguard

import (
	"context"
	"net"
	"os"
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
