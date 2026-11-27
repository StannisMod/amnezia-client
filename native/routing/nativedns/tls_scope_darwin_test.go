//go:build darwin && cgo && !ios

package nativedns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestScopedDarwinTLSRetainsNormalAndNativePolicy(t *testing.T) {
	base := &tls.Config{ServerName: "selected.invalid", MinVersion: tls.VersionTLS12}
	selected, err := scopedTLSConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	if selected == base || selected.RootCAs == nil || selected.VerifyConnection == nil ||
		selected.InsecureSkipVerify || selected.ServerName != base.ServerName ||
		selected.MinVersion != base.MinVersion || base.RootCAs != nil || base.VerifyConnection != nil {
		t.Fatal("scoped trust bypassed normal verification, substituted identity or mutated its template")
	}
	if selected.VerifyConnection(tls.ConnectionState{}) == nil ||
		selected.VerifyConnection(tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}) == nil {
		t.Fatal("native trust accepted absent normal verification or peer certificates")
	}
	closed := &tls.Config{ServerName: "selected.invalid", RootCAs: x509.NewCertPool()}
	if actual, err := scopedTLSConfig(closed); err != nil || actual != closed {
		t.Fatal("explicit original closed test policy was replaced", err)
	}
	for _, invalid := range []*tls.Config{nil, {}, {ServerName: "selected.invalid", InsecureSkipVerify: true}} {
		if _, err := scopedTLSConfig(invalid); err == nil {
			t.Fatal("invalid/bypassed TLS policy accepted")
		}
	}
}

// Hosted macOS only. A unique fixture certificate is the sole owned OS mutation.
// Real native trust/deny settings are used, never custom production roots.
func TestScopedDarwinNativeTrustDenyAndNoFetch(t *testing.T) {
	if os.Getenv("AMNEZIA_DARWIN_NATIVE_TRUST_TEST") != "isolated-fixture" {
		t.Skip("requires the explicitly owned elevated hosted macOS trust fixture")
	}
	var fetched, connections, queries atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched.Add(1)
		http.Error(w, "implicit trust fetch is forbidden", http.StatusForbidden)
	}))
	defer trap.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{CommonName: "Amnezia scoped DNS fixture " + serial.String()},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)),
		DNSNames: []string{"selected.invalid"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer: []string{trap.URL + "/ocsp"}, IssuingCertificateURL: []string{trap.URL + "/issuer"}}
	certificate, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	// Retain failed fixture material and command diagnostics, not private user data.
	directory, err := os.MkdirTemp(os.Getenv("RUNNER_TEMP"), "amnezia-scoped-dns-trust-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("owned trust fixture:", directory)
	caPath := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root}), 0600); err != nil {
		t.Fatal(err)
	}
	security := func(args ...string) error {
		command := append([]string{"-n", "/usr/bin/security"}, args...)
		output, err := exec.Command("/usr/bin/sudo", command...).CombinedOutput()
		t.Logf("security %v: %s", args, output)
		return err
	}
	keychain := "/Library/Keychains/System.keychain"
	fingerprint := fmt.Sprintf("%X", sha1.Sum(root))
	owned := false
	t.Cleanup(func() {
		if !owned {
			return
		}
		if err := security("remove-trusted-cert", "-d", caPath); err != nil {
			t.Error("owned trust settings cleanup failed:", err)
		}
		if err := security("delete-certificate", "-Z", fingerprint, keychain); err != nil {
			t.Error("owned certificate cleanup failed:", err)
		}
		output, err := exec.Command("/usr/bin/security", "find-certificate", "-a", "-Z", keychain).CombinedOutput()
		if err != nil || strings.Contains(strings.ToUpper(string(output)), fingerprint) {
			t.Error("owned certificate absence not confirmed:", err)
		}
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			secure := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12,
				Certificates: []tls.Certificate{{Certificate: [][]byte{certificate, root}, PrivateKey: key}}})
			if secure.Handshake() == nil {
				stream := &dns.Conn{Conn: secure}
				if query, err := stream.ReadMsg(); err == nil {
					queries.Add(1)
					reply := new(dns.Msg).SetReply(query)
					reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{
						Name: "fixture.invalid.", Rrtype: dns.TypeA, Class: dns.ClassINET},
						A: net.IPv4(192, 0, 2, 7)}}
					_ = stream.WriteMsg(reply)
				}
			}
			_ = secure.Close()
		}
	}()
	defer func() { _ = listener.Close(); <-done }()
	endpoint := netip.MustParseAddrPort(listener.Addr().String())
	for phase := 0; phase < 4; phase++ {
		if phase == 1 || phase == 2 {
			setting := "trustRoot"
			if phase == 2 {
				setting = "deny"
			}
			owned = true // Also retain/clean a partially successful native command.
			if err := security("add-trusted-cert", "-d", "-r", setting, "-k", keychain, caPath); err != nil {
				t.Fatal("owned native trust mutation failed:", err)
			}
		}
		if phase == 3 {
			if err := security("add-trusted-cert", "-d", "-r", "trustRoot", "-k", keychain, caPath); err != nil {
				t.Fatal(err)
			}
		}
		name := "selected.invalid"
		if phase == 3 {
			name = "wrong.invalid"
		}
		for _, network := range []string{"udp", "tcp"} {
			var dials atomic.Int32
			exchange, err := EncryptedResolver(EncryptedServer{Address: endpoint, Transport: "tls",
				ServerName: name}, encryptedDial(&dials, endpoint), nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			start := time.Now()
			answer, err := exchange(ctx, network, new(dns.Msg).SetQuestion("fixture.invalid.", dns.TypeA))
			cancel()
			elapsed := time.Since(start)
			t.Logf("phase=%d network=%s elapsed=%s accepted=%v", phase, network, elapsed, err == nil)
			if (err == nil) != (phase == 1) || elapsed >= time.Second || dials.Load() != 1 {
				t.Fatalf("scoped native trust/name decision failed: %v elapsed=%s dials=%d", err, elapsed, dials.Load())
			}
			if phase == 1 {
				if answer == nil || answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
					t.Fatal("authenticated native answer was not preserved:", answer)
				}
				address, ok := answer.Answer[0].(*dns.A)
				if !ok || !address.A.Equal(net.IPv4(192, 0, 2, 7)) {
					t.Fatal("authenticated native A answer changed:", answer)
				}
			}
		}
	}
	if connections.Load() != 8 || queries.Load() != 2 || fetched.Load() != 0 {
		t.Fatalf("unexpected transport: connections=%d queries=%d implicit trust HTTP=%d",
			connections.Load(), queries.Load(), fetched.Load())
	}
}
