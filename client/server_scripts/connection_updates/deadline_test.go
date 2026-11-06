package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIncompleteAckBodiesReleaseAllHandlerSlots(t *testing.T) {
	dir := t.TempDir()
	mustAdmin(t, dir, "init", request{Host: "127.0.0.1"})
	issued := mustAdmin(t, dir, "issue", request{Container: "amnezia-wireguard", ClientPublicKey: testKey('C'), Settings: testSettings("vpn.example.test")})
	state, e := readState(dir)
	if e != nil {
		t.Fatal(e)
	}
	certificate, e := tls.X509KeyPair(pemCertificate(state.Certificate), pemPrivateKey(state.TLSKey))
	if e != nil {
		t.Fatal(e)
	}
	configuration := deliveryHTTPServer(dir, newReadinessBook(), certificate)
	if configuration.ReadTimeout <= 0 || configuration.ReadTimeout > 10*time.Second {
		t.Fatal("production body read deadline is missing or unbounded")
	}
	server := httptest.NewUnstartedServer(configuration.Handler)
	server.Config = configuration
	server.TLS = configuration.TLSConfig.Clone()
	server.StartTLS()
	roots := x509.NewCertPool()
	parsed, e := x509.ParseCertificate(state.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	roots.AddCert(parsed)
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	connections := []net.Conn{}
	defer func() {
		for _, connection := range connections {
			connection.Close()
		}
		server.Close()
	}()
	address := strings.TrimPrefix(server.URL, "https://")
	id, token := issued["id"].(string), issued["token"].(string)
	for i := 0; i < 4; i++ {
		connection, e := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, tlsConfig)
		if e != nil {
			t.Fatal(e)
		}
		connections = append(connections, connection)
		_, e = fmt.Fprintf(connection, "POST /v1/connections/%s/ack HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Length: 1024\r\n\r\n{", id, address, token)
		if e != nil {
			t.Fatal(e)
		}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	fetch := func() int {
		t.Helper()
		req, e := http.NewRequest("GET", server.URL+"/v1/connections/"+id, nil)
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		response, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		response.Body.Close()
		return response.StatusCode
	}
	occupied := false
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		if fetch() == http.StatusServiceUnavailable {
			occupied = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !occupied {
		t.Fatal("fixture did not occupy all four acknowledgement handlers")
	}
	// Keep the clients open and withhold the remaining body bytes. A write/idle
	// timeout alone cannot unblock ReadAll; the production read deadline must.
	until = time.Now().Add(configuration.ReadTimeout + 2*time.Second)
	for time.Now().Before(until) {
		if fetch() == http.StatusOK {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("incomplete acknowledgement bodies retained handler slots beyond the production deadline")
}
