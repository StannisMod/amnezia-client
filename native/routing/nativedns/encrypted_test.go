package nativedns

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func encryptedFixture(t *testing.T, serve func(net.Conn) error) (netip.AddrPort, *x509.CertPool, <-chan error) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"selected.invalid"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := x509.ParseCertificate(root)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{cert, root}, PrivateKey: private}},
			MinVersion: tls.VersionTLS12})
		if err := secure.Handshake(); err != nil {
			done <- err
			return
		}
		if secure.ConnectionState().ServerName != "selected.invalid" {
			done <- fmt.Errorf("wrong SNI")
			return
		}
		done <- serve(secure)
	}()
	return netip.MustParseAddrPort(listener.Addr().String()), roots, done
}

func encryptedDial(calls *atomic.Int32, endpoint netip.AddrPort) Dial {
	return func(ctx context.Context, network string, server netip.AddrPort) (net.Conn, error) {
		calls.Add(1)
		if network != "tcp4" || server != endpoint {
			return nil, fmt.Errorf("scope/endpoint changed")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.String())
	}
}

func TestEncryptedResolverDoTAuthenticatedSelectedScope(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			endpoint, roots, done := encryptedFixture(t, func(conn net.Conn) error {
				stream := &dns.Conn{Conn: conn}
				query, err := stream.ReadMsg()
				if err != nil {
					return err
				}
				answer := new(dns.Msg).SetReply(query)
				answer.AuthenticatedData = true
				answer.Id++
				if err := stream.WriteMsg(answer); err != nil {
					return err
				}
				answer.Id = query.Id
				return stream.WriteMsg(answer)
			})
			var calls atomic.Int32
			exchange, err := EncryptedResolver(EncryptedServer{Address: endpoint, Transport: "tls", ServerName: "selected.invalid"},
				encryptedDial(&calls, endpoint), roots)
			if err != nil {
				t.Fatal(err)
			}
			request := new(dns.Msg).SetQuestion("original.example.", dns.TypeA)
			answer, err := exchange(context.Background(), network, request)
			if err != nil || answer == nil || !answer.AuthenticatedData || answer.Id != request.Id || calls.Load() != 1 {
				t.Fatalf("selected authenticated DoT failed: %v, %v", answer, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEncryptedResolverDoHWireAndNoRedirectOrDowngrade(t *testing.T) {
	for _, mode := range []string{"POST", "GET", "redirect", "wrong-type", "oversize", "wrong-question"} {
		t.Run(mode, func(t *testing.T) {
			endpoint, roots, done := encryptedFixture(t, func(conn net.Conn) error {
				query, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return err
				}
				defer query.Body.Close()
				var wire []byte
				if mode == "GET" {
					if query.Method != "GET" {
						return fmt.Errorf("not GET")
					}
					wire, err = base64.RawURLEncoding.DecodeString(query.URL.Query().Get("dns"))
				} else {
					if query.Method != "POST" || query.Header.Get("Content-Type") != "application/dns-message" {
						return fmt.Errorf("not DNS POST")
					}
					wire, err = io.ReadAll(query.Body)
				}
				if err != nil {
					return err
				}
				request := new(dns.Msg)
				if err := request.Unpack(wire); err != nil {
					return err
				}
				answer := new(dns.Msg).SetReply(request)
				answer.AuthenticatedData = true
				if mode == "wrong-question" {
					answer.Question[0].Name = "substituted.example."
				}
				wire, err = answer.Pack()
				if err != nil {
					return err
				}
				status, kind := "200 OK", "application/dns-message"
				if mode == "redirect" {
					status = "302 Found"
				}
				if mode == "wrong-type" {
					kind = "text/html"
				}
				if mode == "oversize" {
					wire = make([]byte, 65536)
				}
				_, err = fmt.Fprintf(conn, "HTTP/1.1 %s\r\nContent-Type: %s\r\nLocation: https://fallback.invalid/dns-query\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", status, kind, len(wire))
				if err != nil {
					return err
				}
				_, err = conn.Write(wire)
				return err
			})
			template := "https://selected.invalid:" + strconv.Itoa(int(endpoint.Port())) + "/original-path"
			if mode == "GET" {
				template += "{?dns}"
			}
			var calls atomic.Int32
			exchange, err := EncryptedResolver(EncryptedServer{Address: endpoint, Transport: "https", HTTPSURL: template},
				encryptedDial(&calls, endpoint), roots)
			if err != nil {
				t.Fatal(err)
			}
			answer, err := exchange(context.Background(), "udp", new(dns.Msg).SetQuestion("original.example.", dns.TypeA))
			valid := mode == "POST" || mode == "GET"
			if valid && (err != nil || answer == nil || !answer.AuthenticatedData) {
				t.Fatalf("DoH failed: %v", err)
			}
			if !valid && (err == nil || answer != nil) {
				t.Fatal("invalid DoH response accepted")
			}
			if calls.Load() != 1 {
				t.Fatal("DoH redirected/retried/fell back")
			}
			if serverErr := <-done; valid && serverErr != nil {
				t.Fatal(serverErr)
			}
		})
	}
}

func TestEncryptedResolverTLSIdentityAndTrustFailuresNeverFallback(t *testing.T) {
	for _, mode := range []string{"wrong-name", "untrusted"} {
		t.Run(mode, func(t *testing.T) {
			endpoint, roots, done := encryptedFixture(t, func(net.Conn) error { return fmt.Errorf("untrusted session admitted") })
			name := "selected.invalid"
			if mode == "wrong-name" {
				name = "wrong.invalid"
			} else {
				roots = x509.NewCertPool()
			}
			var calls atomic.Int32
			exchange, err := EncryptedResolver(EncryptedServer{Address: endpoint, Transport: "tls", ServerName: name},
				encryptedDial(&calls, endpoint), roots)
			if err != nil {
				t.Fatal(err)
			}
			answer, err := exchange(context.Background(), "tcp", new(dns.Msg).SetQuestion("original.example.", dns.TypeA))
			if err == nil || answer != nil || calls.Load() != 1 {
				t.Fatal("TLS identity/trust bypassed")
			}
			if <-done == nil {
				t.Fatal("server accepted rejected TLS session")
			}
		})
	}
}

func TestEncryptedResolverIPv6AndInvalidMetadataNeverDial(t *testing.T) {
	var calls atomic.Int32
	dial := func(context.Context, string, netip.AddrPort) (net.Conn, error) {
		calls.Add(1)
		return nil, fmt.Errorf("unexpected dial")
	}
	exchange, err := EncryptedResolver(EncryptedServer{Address: netip.MustParseAddrPort("[fd77::53]:853"), Transport: "tls"}, dial, nil)
	if err != nil {
		t.Fatal(err)
	}
	if answer, err := exchange(context.Background(), "udp", new(dns.Msg).SetQuestion("original.example.", dns.TypeA)); err == nil || answer != nil {
		t.Fatal("IPv6 transport permitted")
	}
	for _, url := range []string{"http://selected.invalid/dns-query", "https://user:secret@selected.invalid/dns-query",
		"https://selected.invalid/dns-query#fragment", "https://selected.invalid:8443/dns-query", "https://selected.invalid/{unknown}"} {
		if _, err := EncryptedResolver(EncryptedServer{Address: netip.MustParseAddrPort("192.0.2.53:443"), Transport: "https", HTTPSURL: url}, dial, nil); err == nil {
			t.Fatalf("admitted %s", url)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid/IPv6 selection performed bootstrap")
	}
}

func TestSelectedResolverNeverErasesSecurityMetadata(t *testing.T) {
	dial := func(context.Context, string, netip.AddrPort) (net.Conn, error) {
		t.Fatal("configuration performed network I/O")
		return nil, nil
	}
	address := netip.MustParseAddrPort("192.0.2.53:53")
	for _, selected := range []EncryptedServer{
		{Address: address, Transport: "plain", ServerName: "selected.invalid"},
		{Address: address, HTTPSURL: "https://selected.invalid/dns-query"},
		{Address: address, Transport: "opportunistic"},
		{Address: address, Transport: "tls", HTTPSURL: "https://selected.invalid/dns-query"},
	} {
		if _, err := SelectedResolver(selected, dial, nil); err == nil {
			t.Fatal("erased unsupported selected metadata", selected)
		}
	}
	for _, transport := range []string{"", "plain"} {
		if _, err := SelectedResolver(EncryptedServer{Address: address, Transport: transport}, dial, nil); err != nil {
			t.Fatal("legacy plaintext configuration changed", err)
		}
	}
}

func TestEncryptedResolverCancellationRetainsBlockedScopeBind(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var peer net.Conn
	exchange, err := EncryptedResolver(EncryptedServer{Address: netip.MustParseAddrPort("192.0.2.53:853"), Transport: "tls"},
		func(context.Context, string, netip.AddrPort) (net.Conn, error) {
			close(entered)
			<-release
			conn, other := net.Pipe()
			peer = other
			return conn, nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := exchange(ctx, "tcp", new(dns.Msg).SetQuestion("original.example.", dns.TypeA))
		done <- err
	}()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("released an in-flight selected-scope bind")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("late bind admitted TLS")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled exchange did not join")
	}
	defer peer.Close()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := peer.Read(b[:]); err == nil || !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("selected socket was not closed: %v", err)
	}
}
