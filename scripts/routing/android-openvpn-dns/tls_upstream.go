// Test-only selected DNS upstream. Never packaged in a production runtime.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

func reply(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	answer := append([]byte(nil), query...)
	answer[2] |= 0x80
	answer[3] = 0xa0
	answer[6], answer[7] = 0, 1
	return append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 2)
}

func main() {
	if len(os.Args) != 2 {
		panic("test CA path required")
	}
	// P-256 is supported by the native Windows certificate-chain verifier too;
	// a host-only Ed25519 CA is not evidence of Windows trust acceptance.
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "native DNS test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &private.PublicKey, private)
	if err != nil {
		panic(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"selected.invalid"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, leaf, ca, &private.PublicKey, private)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root}), 0600); err != nil {
		panic(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{cert, root}, PrivateKey: private}},
		MinVersion: tls.VersionTLS12}
	dot, err := tls.Listen("tcp4", "127.0.0.1:0", config)
	if err != nil {
		panic(err)
	}
	doh, err := tls.Listen("tcp4", "127.0.0.1:0", config)
	if err != nil {
		panic(err)
	}
	plain, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	plainUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: plain.Addr().(*net.TCPAddr).Port})
	if err != nil {
		panic(err)
	}
	var dotQueries, dohQueries, dohConnections, dohGetQueries, dohPostQueries, plainTCPQueries, plainUDPQueries atomic.Uint32
	var workers sync.WaitGroup
	serveStream := func(listener net.Listener, counter *atomic.Uint32) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					var length [2]byte
					if _, err := io.ReadFull(conn, length[:]); err != nil {
						return
					}
					query := make([]byte, binary.BigEndian.Uint16(length[:]))
					if _, err := io.ReadFull(conn, query); err != nil {
						return
					}
					counter.Add(1)
					answer := reply(query)
					binary.BigEndian.PutUint16(length[:], uint16(len(answer)))
					_, _ = conn.Write(append(length[:], answer...))
				}()
			}
		}()
	}
	serveStream(dot, &dotQueries)
	serveStream(plain, &plainTCPQueries)
	workers.Add(1)
	go func() {
		defer workers.Done()
		var packet [65535]byte
		for {
			size, peer, err := plainUDP.ReadFromUDP(packet[:])
			if err != nil {
				return
			}
			plainUDPQueries.Add(1)
			_, _ = plainUDP.WriteToUDP(reply(packet[:size]), peer)
		}
	}()
	server := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				dohConnections.Add(1)
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/selected-dns" || (r.Method != "POST" && r.Method != "GET") {
				http.Error(w, "invalid selected DNS request", http.StatusBadRequest)
				return
			}
			var query []byte
			var err error
			if r.Method == "GET" {
				values := r.URL.Query()
				if len(values) != 1 || len(values["dns"]) != 1 {
					http.Error(w, "invalid selected DNS template", http.StatusBadRequest)
					return
				}
				query, err = base64.RawURLEncoding.DecodeString(values.Get("dns"))
			} else {
				if r.Header.Get("Content-Type") != "application/dns-message" {
					http.Error(w, "invalid selected DNS media type", http.StatusBadRequest)
					return
				}
				query, err = io.ReadAll(io.LimitReader(r.Body, 65536))
			}
			if err != nil || len(query) > 65535 {
				http.Error(w, "invalid DNS frame", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			if r.Method == "GET" {
				dohGetQueries.Add(1)
			} else {
				dohPostQueries.Add(1)
			}
			dohQueries.Add(1)
			_, _ = w.Write(reply(query))
		})}
	workers.Add(1)
	go func() { defer workers.Done(); _ = server.Serve(doh) }()
	port := doh.Addr().(*net.TCPAddr).Port
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
		"dot": dot.Addr().String(), "doh": doh.Addr().String(),
		"url": "https://selected.invalid:" + strconv.Itoa(port) + "/selected-dns",
		"ca":  os.Args[1], "name": "selected.invalid", "plain": plain.Addr().String(),
	})
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = dot.Close()
	_ = plain.Close()
	_ = plainUDP.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		panic(err)
	}
	workers.Wait()
	_ = json.NewEncoder(os.Stdout).Encode(map[string]uint32{
		"dot_queries": dotQueries.Load(), "doh_queries": dohQueries.Load(),
		"doh_connections": dohConnections.Load(),
		"doh_get_queries": dohGetQueries.Load(), "doh_post_queries": dohPostQueries.Load(),
		"plain_tcp_queries": plainTCPQueries.Load(), "plain_udp_queries": plainUDPQueries.Load(),
	})
}
