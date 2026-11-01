package awg

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

// This is real QUIC/TLS over the AWG inner UDP transport, including stream
// segmentation at MTU 1280. It does not claim native app/TUN QUIC acceptance.
func TestAWG31QUIC(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) { testAWG31QUIC(t, "10.77.0.1", "10.77.0.2", "/32") })
	t.Run("IPv6", func(t *testing.T) { testAWG31QUIC(t, "fd77::1", "fd77::2", "/128") })
}

func testAWG31QUIC(t *testing.T, clientIP, serverIP, mask string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	aPriv, aPub := keypair(t)
	bPriv, bPub := keypair(t)
	var lc net.ListenConfig
	params := map[string]string{"s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}
	serverConfig := Config{Address: []netip.Addr{netip.MustParseAddr(serverIP)}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix(clientIP + mask)}, Parameters: params, MTU: 1280}
	b, err := New(ctx, serverConfig, lc.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	port, err := b.LocalPort()
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(ctx, Config{Address: []netip.Addr{netip.MustParseAddr(clientIP)}, PrivateKey: aPriv, PublicKey: bPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), AllowedIPs: []netip.Prefix{netip.MustParsePrefix(serverIP + mask)}, Parameters: params, MTU: 1280}, lc.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	clientPort, err := a.LocalPort()
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	serverConfig.ListenPort = port
	serverConfig.Endpoint = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), clientPort)
	b, err = New(ctx, serverConfig, lc.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"routing-fixture.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"amnezia-test-quic"}, MinVersion: tls.VersionTLS13}
	clientTLS := &tls.Config{RootCAs: roots, ServerName: "routing-fixture.invalid", NextProtos: serverTLS.NextProtos, MinVersion: tls.VersionTLS13}
	serverUDP, err := b.Net.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverIP), 18443))
	if err != nil {
		t.Fatal(err)
	}
	defer serverUDP.Close()
	options := &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true}
	listener, err := quic.Listen(serverUDP, serverTLS, options)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	finishServer, serverClosed := make(chan struct{}), make(chan struct{})
	defer func() { cancel(); listener.Close(); close(finishServer); <-serverClosed }()
	go func() {
		defer close(serverClosed)
		conn, err := listener.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		data, err := io.ReadAll(io.LimitReader(stream, 128<<10))
		if err == nil {
			sum := sha256.Sum256(data)
			_, err = stream.Write(sum[:])
		}
		if err == nil {
			err = stream.Close()
		}
		done <- err
		<-finishServer
	}()
	udp, err := a.DialContext(ctx, "udp", net.JoinHostPort(serverIP, "18443"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	conn, err := quic.DialConn(ctx, udp, clientTLS, options)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("QUIC over AWG 3.1"), 4096)
	if _, err = stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)
	if !bytes.Equal(got, want[:]) {
		t.Fatal("QUIC stream payload changed")
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
