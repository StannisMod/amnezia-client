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

// Allow a bounded integration exchange through the race-instrumented userspace
// VPN stack on shared runners, including transport/handshake retransmission.
const sniffStreamTimeout = 15 * time.Second

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
			serverErrors := make(chan string, 8)
			dumpServerErrors := func() {
				for {
					select {
					case message := <-serverErrors:
						t.Log(message)
					default:
						return
					}
				}
			}
			serve := func(l net.Listener, label string) {
				for {
					c, e := l.Accept()
					if e != nil {
						return
					}
					go func() {
						defer c.Close()
						started := time.Now()
						reportError := func(stage string, err error) {
							select {
							case serverErrors <- fmt.Sprintf("%s %s after %s: %v", label, stage, time.Since(started), err):
							default:
							}
						}
						c.SetDeadline(time.Now().Add(sniffStreamTimeout))
						if protocol == "tls" {
							c = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
							if e := c.(*tls.Conn).Handshake(); e != nil {
								reportError("TLS handshake", e)
								return
							}
							var p [4]byte
							if _, e := io.ReadFull(c, p[:]); e != nil || string(p[:]) != "ping" {
								reportError("TLS request", e)
								return
							}
						} else {
							r, e := http.ReadRequest(bufio.NewReader(c))
							if e != nil || r.Host == "" {
								reportError("HTTP request", e)
								return
							}
							r.Body.Close()
						}
						if _, err := io.WriteString(c, label); err != nil {
							reportError("response", err)
						}
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
				var app, capture net.Conn
				if protocol == "tls" {
					// TLS can emit post-handshake records while the client is
					// writing application data. A zero-buffer net.Pipe can
					// couple those writes and stall under race instrumentation;
					// use the buffered TCP stream a browser actually provides.
					app, capture = sniffTCPPair(t)
				} else {
					app, capture = net.Pipe()
				}
				app.SetDeadline(time.Now().Add(sniffStreamTimeout))
				go instance.Router().RouteConnectionEx(ctx, capture, adapter.InboundContext{Inbound: TUNTag, Network: "tcp", Destination: M.Socksaddr{Addr: destination, Port: port}}, nil)
				var client net.Conn = app
				if protocol == "tls" {
					client = tls.Client(app, &tls.Config{RootCAs: roots, ServerName: tc.name, MinVersion: tls.VersionTLS12})
					if err := client.(*tls.Conn).Handshake(); err != nil {
						app.Close()
						dumpServerErrors()
						t.Fatal(tc, err)
					}
					_, err = client.Write([]byte("ping"))
				} else {
					_, err = client.Write([]byte("GET / HTTP/1.1\r\nHost: " + tc.name + "\r\n\r\n"))
				}
				if err != nil {
					app.Close()
					dumpServerErrors()
					t.Fatal(tc, err)
				}
				response := make([]byte, len(tc.want))
				_, err = io.ReadFull(client, response)
				// Only routing and authenticated data are asserted here. Close
				// the owned stream without waiting for a TLS shutdown exchange.
				app.Close()
				if err != nil || string(response) != tc.want {
					dumpServerErrors()
					t.Fatalf("%s (%s, fake=%v): got %q, %v", protocol, tc.name, tc.fake, response, err)
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

func sniffTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	app, err := net.DialTimeout("tcp4", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := listener.Accept()
	if err != nil {
		app.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		app.Close()
		capture.Close()
	})
	return app, capture
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
