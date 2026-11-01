// Package fixturequic supplies disposable native QUIC/TLS acceptance probes.
// It is used only by test tools, never by the shipping client/helper.
package fixturequic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	quic "github.com/sagernet/quic-go"
)

const Port = 18443
const serverName = "routing-fixture.invalid"
const payloadSize = 64 << 10

var options = &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true}

func Certificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{serverName}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func Serve(pc net.PacketConn, cert tls.Certificate, label string) (io.Closer, error) {
	listener, err := quic.Listen(pc, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"amnezia-native-quic"}, MinVersion: tls.VersionTLS13}, options)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				defer conn.CloseWithError(0, "")
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				stream, err := conn.AcceptStream(ctx)
				if err != nil {
					return
				}
				stream.SetDeadline(time.Now().Add(15 * time.Second))
				data := make([]byte, payloadSize)
				if _, err = io.ReadFull(stream, data); err != nil {
					return
				}
				sum := sha256.Sum256(data)
				if _, err = stream.Write(append([]byte(label+":"), sum[:]...)); err != nil {
					return
				}
				// Keep the connection alive until the client has received and
				// verified the digest, rather than racing its final QUIC packets.
				var ack [1]byte
				io.ReadFull(stream, ack[:])
				stream.Close()
			}()
		}
	}()
	return listener, nil
}

// Probe uses an ordinary native UDP socket. A successful digest proves real
// application -> OS capture -> proxy -> observer transfer at MTU 1280.
func Probe(address, caPath string) (string, error) {
	der, err := os.ReadFile(caPath)
	if err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var dialer net.Dialer
	udp, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return "", err
	}
	defer udp.Close()
	conn, err := quic.DialConn(ctx, udp, &tls.Config{RootCAs: roots, ServerName: serverName, NextProtos: []string{"amnezia-native-quic"}, MinVersion: tls.VersionTLS13}, options)
	if err != nil {
		return "", err
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return "", err
	}
	stream.SetDeadline(time.Now().Add(12 * time.Second))
	data := bytes.Repeat([]byte{0x51, 0x55, 0x49, 0x43}, payloadSize/4)
	if _, err = stream.Write(data); err != nil {
		return "", err
	}
	// Read a bounded prefix, then the remaining DIRECT label/digest if needed.
	response := make([]byte, 4+sha256.Size)
	if _, err = io.ReadFull(stream, response); err != nil {
		return "", err
	}
	label := "VPN"
	if bytes.HasPrefix(response, []byte("DIRE")) {
		rest := make([]byte, 3)
		if _, err = io.ReadFull(stream, rest); err != nil {
			return "", err
		}
		response = append(response, rest...)
		label = "DIRECT"
	}
	sum := sha256.Sum256(data)
	if !bytes.Equal(response, append([]byte(label+":"), sum[:]...)) {
		return "", errors.New("native QUIC observer/digest mismatch")
	}
	if _, err = stream.Write([]byte{1}); err != nil {
		return "", err
	}
	stream.Close()
	return label, nil
}
