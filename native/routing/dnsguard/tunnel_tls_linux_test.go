package dnsguard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/nativedns"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestNativeTunnelEncryptedResolverAuthenticatesOverExistingEngine(t *testing.T) {
	// Explicit ORIGINAL test trust policy, not an override in the production
	// constructor (which still uses normal system trust). No insecure TLS.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1),
		DNSNames: []string{"selected.invalid"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	remote, err := newPacketEndpoint(netip.MustParseAddr("10.8.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	listener, err := gonet.ListenTCP(remote.stack, tcpip.FullAddress{
		NIC: 1, Addr: tcpip.AddrFromSlice([]byte{10, 8, 0, 1}), Port: 853,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	secure := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}})
	var requests atomic.Int32
	server := &dns.Server{Listener: secure, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		requests.Add(1)
		a := new(dns.Msg).SetReply(q)
		a.AuthenticatedData = true
		record, _ := dns.NewRR("native-engine-tls.test. 60 IN A 198.51.100.2")
		a.Answer = []dns.RR{record}
		_ = w.WriteMsg(a)
	})}
	ready, serverDone := make(chan struct{}), make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { defer close(serverDone); _ = server.ActivateAndServe() }()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("selected TLS peer did not start")
	}
	defer func() { server.Shutdown(); <-serverDone }()
	var releases, failures atomic.Int32
	callbacks := packetCallbacks(&releases)
	callbacks.Dispatch, callbacks.Cancel = nil, nil
	callbacks.Failed = func() { failures.Add(1) }
	selected := nativedns.EncryptedServer{Address: netip.MustParseAddrPort("10.8.0.1:853"),
		Transport: "tls", ServerName: "selected.invalid"}
	session, err := NewTunnelPacketSession(context.Background(),
		netip.MustParseAddr("198.19.255.1"), netip.MustParseAddr("10.8.0.2"), 576, selected,
		func(packet []byte) bool {
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(append([]byte(nil), packet...)),
			})
			remote.link.InjectInbound(ipv4.ProtocolNumber, pkt)
			pkt.DecRef()
			return true
		}, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
		for {
			n, err := remote.Read(data, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				session.FeedTunnel(data[0][:sizes[0]])
			}
		}
	}()
	defer func() { session.Close(); remote.Close(); <-pumpDone }()
	exchange, err := nativedns.SelectedResolver(selected, session.tunnel.dial, roots)
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("native-engine-tls.test.", dns.TypeA)
	for _, network := range []string{"udp", "tcp"} {
		a, err := exchange(context.Background(), network, q)
		if err != nil || a == nil || len(a.Answer) != 1 || !a.AuthenticatedData {
			t.Fatalf("encrypted native-engine %s exchange: %v / %v", network, a, err)
		}
	}
	wrongName := selected
	wrongName.ServerName = "wrong.invalid"
	for _, invalid := range []struct {
		server nativedns.EncryptedServer
		roots  *x509.CertPool
	}{{wrongName, roots}, {selected, x509.NewCertPool()}} {
		exchange, err := nativedns.SelectedResolver(invalid.server, session.tunnel.dial, invalid.roots)
		if err != nil {
			t.Fatal(err)
		}
		if a, err := exchange(context.Background(), "udp", q); err == nil || a != nil {
			t.Fatal("native-engine TLS validation bypassed or downgraded")
		}
	}
	if requests.Load() != 2 {
		t.Fatal("invalid TLS scope reached DNS or fell back to plaintext")
	}
	session.Close()
	if releases.Load() != 1 || failures.Load() != 0 {
		t.Fatal("encrypted tunnel owner did not retire cleanly")
	}
}
