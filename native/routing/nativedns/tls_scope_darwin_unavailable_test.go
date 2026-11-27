//go:build darwin && (!cgo || ios)

package nativedns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestUnrepresentableDarwinSystemTrustNeverDials(t *testing.T) {
	dial := func(context.Context, string, netip.AddrPort) (net.Conn, error) {
		t.Fatal("unrepresentable trust used online system verification or a transport fallback")
		return nil, ErrScopeUnavailable
	}
	exchange, err := EncryptedResolver(EncryptedServer{Address: netip.MustParseAddrPort("192.0.2.53:853"),
		Transport: "tls", ServerName: "selected.invalid"}, dial, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(context.Background(), "udp", new(dns.Msg).SetQuestion("selected.invalid.", dns.TypeA)); err == nil {
		t.Fatal("missing original trust snapshot was accepted")
	}
	closed := &tls.Config{ServerName: "selected.invalid", RootCAs: x509.NewCertPool()}
	if actual, err := scopedTLSConfig(closed); err != nil || actual != closed {
		t.Fatal("explicit original closed trust policy was replaced", err)
	}
}
