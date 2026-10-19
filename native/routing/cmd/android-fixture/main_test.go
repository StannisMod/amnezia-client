//go:build !android && !ios

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/miekg/dns"
)

// Verify the fixture peer really learns an authenticated ephemeral endpoint;
// production's pinned-endpoint outbound is unchanged by the test server.
func TestEmulatorPeerLearnsEndpointAndServesIPv4IPv6(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	f := &fixture{server: server, client: client}
	if err := f.start(); err != nil {
		t.Fatal(err)
	}
	defer f.stop()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transport, err := awg.New(ctx, awg.Config{
		Address:    []netip.Addr{netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("fd77::1")},
		PrivateKey: base64.StdEncoding.EncodeToString(client.Bytes()), PublicKey: base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()),
		Endpoint: netip.MustParseAddrPort("127.0.0.1:51820"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		Parameters: map[string]string{"jc": "3", "jmin": "40", "jmax": "80", "s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"},
	}, func(ctx context.Context, network, address string) (net.PacketConn, error) {
		var lc net.ListenConfig
		return lc.ListenPacket(ctx, network, address)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	for _, ip := range []string{sharedIP, "fd77::2"} {
		c, err := transport.DialContext(ctx, "tcp", net.JoinHostPort(ip, "18081"))
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		data, err := io.ReadAll(c)
		c.Close()
		if err != nil || string(data) != "VPN\n" {
			t.Fatalf("TCP observer: %q, %v", data, err)
		}
		u, err := transport.DialContext(ctx, "udp", net.JoinHostPort(ip, "18082"))
		if err != nil {
			t.Fatal(err)
		}
		u.SetDeadline(time.Now().Add(3 * time.Second))
		u.Write([]byte("probe"))
		buf := make([]byte, 32)
		n, err := u.Read(buf)
		u.Close()
		if err != nil || string(buf[:n]) != "VPN:probe" {
			t.Fatalf("UDP observer: %q, %v", buf[:n], err)
		}
	}
	for _, query := range []struct {
		name    string
		kind    uint16
		answers int
	}{{"cname.test.", dns.TypeA, 2}, {"ipv6.test.", dns.TypeA, 0}, {"ipv6.test.", dns.TypeAAAA, 1}} {
		c, err := transport.DialContext(ctx, "udp", "10.77.0.2:53")
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		q := new(dns.Msg)
		q.SetQuestion(query.name, query.kind)
		raw, _ := q.Pack()
		c.Write(raw)
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
		a := new(dns.Msg)
		if err := a.Unpack(buf[:n]); err != nil || len(a.Answer) != query.answers {
			t.Fatal("fixture DNS answer mismatch", query.name, err)
		}
	}
	if f.vpnTCP.Load() != 2 || f.vpnUDP.Load() != 2 {
		t.Fatal("observer counters do not reflect actual flows")
	}
}
