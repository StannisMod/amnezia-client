package engine

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	quic "github.com/sagernet/quic-go"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	SBuf "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// The browser has already resolved the name outside managed DNS (e.g. DoH).
// Both names connect to the same real IP; only Host/SNI can select the exit.
func testRealIPSniff(t *testing.T, ctx context.Context, instance *box.Box, peer *awg.Transport) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"sniff.ru", "sniff.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	for _, protocol := range []string{"http", "tls"} {
		t.Run("real_ip_"+protocol, func(t *testing.T) {
			physical, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer physical.Close()
			port := uint16(physical.Addr().(*net.TCPAddr).Port)
			virtual, err := peer.Net.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.77.0.2"), port))
			if err != nil {
				t.Fatal(err)
			}
			defer virtual.Close()
			type observerResult struct {
				label string
				err   error
			}
			observed := make(chan observerResult, 3)
			serve := func(l net.Listener, label string) {
				for {
					c, e := l.Accept()
					if e != nil {
						return
					}
					go func() {
						// Report every observer phase. Previously an expired
						// observer deadline was swallowed, leaving only a
						// misleading client-side read timeout in CI.
						defer c.Close()
						observed <- observerResult{label, serveSniffObserver(c, protocol, cert, label)}
					}()
				}
			}
			go serve(physical, "DIRECT")
			go serve(virtual, "TUNNEL")
			for _, tc := range []struct {
				name, want string
				fake       bool
			}{{"sniff.ru", "DIRECT", false}, {"sniff.test", "TUNNEL", false}, {"sniff.test", "DIRECT", true}} {
				destination := netip.MustParseAddr("10.77.0.2")
				if tc.fake {
					manager := service.FromContext[adapter.DNSTransportManager](ctx)
					transport, _ := manager.Transport("fake")
					destination, err = transport.(adapter.FakeIPTransport).Store().Create("sniff.ru", false)
					if err != nil {
						t.Fatal(err)
					}
				}
				app, capture := net.Pipe()
				app.SetDeadline(time.Now().Add(sniffOperationTimeout))
				go instance.Router().RouteConnectionEx(ctx, capture, adapter.InboundContext{Inbound: TUNTag, Network: "tcp", Destination: M.Socksaddr{Addr: destination, Port: port}}, nil)
				var client net.Conn = app
				if protocol == "tls" {
					client = tls.Client(app, &tls.Config{RootCAs: roots, ServerName: tc.name, MinVersion: tls.VersionTLS12})
					if err := client.(*tls.Conn).Handshake(); err != nil {
						app.Close()
						t.Fatal(tc, err)
					}
					app.SetDeadline(time.Now().Add(sniffOperationTimeout))
					_, err = client.Write([]byte("ping"))
				} else {
					_, err = client.Write([]byte("GET / HTTP/1.1\r\nHost: " + tc.name + "\r\n\r\n"))
				}
				if err != nil {
					app.Close()
					t.Fatal(tc, err)
				}
				response := make([]byte, len(tc.want))
				_, err = io.ReadFull(client, response)
				if err != nil || string(response) != tc.want {
					app.Close()
					select {
					case result := <-observed:
						t.Fatalf("%s (%s, fake=%v): got %q, %v; observer %s: %v", protocol, tc.name, tc.fake, response, err, result.label, result.err)
					case <-time.After(sniffOperationTimeout):
						t.Fatalf("%s (%s, fake=%v): got %q, %v; observer did not finish", protocol, tc.name, tc.fake, response, err)
					}
				}
				// Keep the observer open until the authenticated marker has
				// actually reached the client. This separates egress proof
				// from TCP/TLS shutdown, as the QUIC fixture already does.
				_, err = client.Write([]byte{1})
				if err != nil {
					app.Close()
					t.Fatal("observer acknowledgement:", err)
				}
				select {
				case result := <-observed:
					app.Close()
					if result.label != tc.want || result.err != nil {
						t.Fatal("observer:", result.label, result.err)
					}
				case <-time.After(sniffOperationTimeout):
					app.Close()
					t.Fatal("observer did not consume acknowledgement")
				}

			}
		})
	}
	t.Run("real_ip_quic", func(t *testing.T) {
		physical, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer physical.Close()
		port := uint16(physical.LocalAddr().(*net.UDPAddr).Port)
		virtual, err := peer.Net.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.77.0.2"), port))
		if err != nil {
			t.Fatal(err)
		}
		defer virtual.Close()
		options := &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true}
		for _, row := range []struct {
			pc    net.PacketConn
			label string
		}{{physical, "DIRECT"}, {virtual, "TUNNEL"}} {
			listener, err := quic.Listen(row.pc, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"sniff-test"}}, options)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func(label string) {
				for {
					conn, e := listener.Accept(ctx)
					if e != nil {
						return
					}
					go func() {
						defer conn.CloseWithError(0, "")
						stream, e := conn.AcceptStream(ctx)
						if e != nil {
							return
						}
						var ping [4]byte
						if _, e = io.ReadFull(stream, ping[:]); e != nil || string(ping[:]) != "ping" {
							return
						}
						stream.Write([]byte(label))
						var ack [1]byte
						io.ReadFull(stream, ack[:])
					}()
				}
			}(row.label)
		}
		for _, row := range []struct{ name, want string }{{"sniff.ru", "DIRECT"}, {"sniff.test", "TUNNEL"}} {
			app, capture := net.Pipe()
			dst := M.Socksaddr{Addr: netip.MustParseAddr("10.77.0.2"), Port: port}
			closed := make(chan error, 1)
			go instance.Router().RoutePacketConnectionEx(ctx, SBuf.NewUnbindPacketConnWithAddr(capture, dst), adapter.InboundContext{Inbound: TUNTag, Network: "udp", Destination: dst}, func(e error) { closed <- e })
			pc := &sniffTestPackets{Conn: app, remote: net.UDPAddrFromAddrPort(dst.AddrPort())}
			transport := &quic.Transport{Conn: pc}
			conn, err := transport.Dial(ctx, pc.remote, &tls.Config{RootCAs: roots, ServerName: row.name, NextProtos: []string{"sniff-test"}}, options)
			if err != nil {
				transport.Close()
				app.Close()
				select {
				case reason := <-closed:
					t.Log("router:", reason)
				default:
				}
				t.Fatal(row, err)
			}
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			stream.SetDeadline(time.Now().Add(4 * time.Second))
			stream.Write([]byte("ping"))
			result := make([]byte, len(row.want))
			_, err = io.ReadFull(stream, result)
			stream.Write([]byte{1})
			conn.CloseWithError(0, "")
			transport.Close()
			app.Close()
			if err != nil || string(result) != row.want {
				t.Fatalf("QUIC %s: %q, %v", row.name, result, err)
			}
		}
	})

}

// Each phase gets an independent bound: a race-instrumented TLS handshake
// must not consume the time reserved for reading the request and response.
// The parent fixture still bounds the entire DNS/HTTP/TLS/QUIC sequence.
const sniffOperationTimeout = 10 * time.Second

func serveSniffObserver(conn net.Conn, protocol string, cert tls.Certificate, label string) error {
	conn.SetDeadline(time.Now().Add(sniffOperationTimeout))
	if protocol == "tls" {
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("TLS handshake: %w", err)
		}
		conn = tlsConn
	}
	conn.SetDeadline(time.Now().Add(sniffOperationTimeout))
	if protocol == "tls" {
		var ping [4]byte
		if _, err := io.ReadFull(conn, ping[:]); err != nil {
			return fmt.Errorf("request read: %w", err)
		}
		if string(ping[:]) != "ping" {
			return fmt.Errorf("unexpected request %q", ping)
		}
	} else {
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return fmt.Errorf("HTTP request: %w", err)
		}
		request.Body.Close()
		if request.Host == "" {
			return fmt.Errorf("missing HTTP Host")
		}
	}
	conn.SetDeadline(time.Now().Add(sniffOperationTimeout))
	if _, err := io.WriteString(conn, label); err != nil {
		return fmt.Errorf("response write: %w", err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		return fmt.Errorf("response acknowledgement: %w", err)
	}
	if ack[0] != 1 {
		return fmt.Errorf("invalid response acknowledgement")
	}
	return nil
}

type sniffTestPackets struct {
	net.Conn
	remote net.Addr
}

func (p *sniffTestPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	n, e := p.Read(b)
	return n, p.remote, e
}
func (p *sniffTestPackets) WriteTo(b []byte, _ net.Addr) (int, error) { return p.Write(b) }
func (p *sniffTestPackets) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

// Map only the fixture's physical UDP observer; AWG sockets and DNS keep
// their real loopback destinations. This is the UDP equivalent of test DialContext.
type sniffMappedPackets struct {
	net.PacketConn
	mapped atomic.Bool
}

func (p *sniffMappedPackets) WriteTo(b []byte, a net.Addr) (int, error) {
	if u, ok := a.(*net.UDPAddr); ok && u.IP.Equal(net.ParseIP("10.77.0.2")) {
		p.mapped.Store(true)
		a = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: u.Port}
	}
	return p.PacketConn.WriteTo(b, a)
}
func (p *sniffMappedPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, e := p.PacketConn.ReadFrom(b)
	if u, ok := a.(*net.UDPAddr); ok && p.mapped.Load() && u.IP.IsLoopback() {
		a = &net.UDPAddr{IP: net.ParseIP("10.77.0.2"), Port: u.Port}
	}
	return n, a, e
}
