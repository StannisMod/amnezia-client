package nativedns

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// EncryptedServer is the original selected numeric endpoint and TLS identity.
// HTTPSURL is the original DoH URI (optionally ending in the RFC8484 {?dns}
// template). An absent TLS name validates the endpoint IP, never a guessed name.
type EncryptedServer struct {
	Address    netip.AddrPort
	Transport  string // "tls" or "https"; never opportunistic plaintext fallback.
	ServerName string
	HTTPSURL   string
}

// SelectedResolver rejects metadata it cannot represent; plaintext is never a
// fallback for a failed/unknown encrypted transport.
func SelectedResolver(server EncryptedServer, dial Dial, roots *x509.CertPool) (Exchange, error) {
	if server.Transport == "" || server.Transport == "plain" {
		if server.ServerName != "" || server.HTTPSURL != "" || roots != nil {
			return nil, ErrScopeUnavailable
		}
		return Resolver(server.Address, dial)
	}
	return EncryptedResolver(server, dial, roots)
}

// EncryptedResolver uses the SAME explicit scope dialer as plaintext Resolver.
// roots, if supplied, must come from the original platform trust policy.
// No TLS bypass/configuration callbacks, background HTTP dial pool, proxy,
// redirect, hostname bootstrap or resolver substitution is exposed here.
func EncryptedResolver(server EncryptedServer, dial Dial, roots *x509.CertPool) (Exchange, error) {
	if _, err := Resolver(server.Address, dial); err != nil {
		return nil, err
	}
	if strings.ContainsAny(server.ServerName, "\x00\r\n/") {
		return nil, ErrScopeUnavailable
	}
	var endpoint *url.URL
	get := false
	switch server.Transport {
	case "tls":
		if server.HTTPSURL != "" {
			return nil, ErrScopeUnavailable
		}
	case "https":
		text := server.HTTPSURL
		if strings.HasSuffix(text, "{?dns}") {
			get = true
			text = strings.TrimSuffix(text, "{?dns}")
		}
		if strings.ContainsAny(text, "{}\r\n\x00") {
			return nil, ErrScopeUnavailable
		}
		var err error
		endpoint, err = url.Parse(text)
		if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" ||
			endpoint.User != nil || endpoint.Fragment != "" || endpoint.Opaque != "" {
			return nil, ErrScopeUnavailable
		}
		port := endpoint.Port()
		if port == "" {
			port = "443"
		}
		if port != strconv.Itoa(int(server.Address.Port())) ||
			(get && endpoint.RawQuery != "") {
			return nil, ErrScopeUnavailable
		}
		if server.ServerName == "" {
			server.ServerName = endpoint.Hostname()
		}
	default:
		return nil, ErrScopeUnavailable
	}
	if server.ServerName == "" {
		server.ServerName = server.Address.Addr().String()
	}
	var trust *x509.CertPool
	if roots != nil {
		trust = roots.Clone()
	}
	config := &tls.Config{ServerName: server.ServerName, RootCAs: trust, MinVersion: tls.VersionTLS12}
	if endpoint != nil {
		// Manual HTTP/1.1 exchange keeps socket/bind ownership synchronous.
		// No net/http transport may outlive a canceled exchange's host lease.
		config.NextProtos = []string{"http/1.1"}
	}
	return func(parent context.Context, network string, request *dns.Msg) (*dns.Msg, error) {
		if parent == nil || request == nil || request.Response ||
			!server.Address.Addr().Is4() || (network != "udp" && network != "tcp") {
			return nil, ErrScopeUnavailable
		}
		request = request.Copy()
		wire, err := request.Pack()
		if err != nil || len(wire) > 65535 {
			return nil, ErrScopeUnavailable
		}
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		selectedConfig, err := scopedTLSConfig(config)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := dial(ctx, "tcp4", server.Address)
		if err != nil || conn == nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, ErrScopeUnavailable
		}
		defer conn.Close()
		cancelDone := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { defer close(cancelDone); _ = conn.Close() })
		defer func() {
			if !stop() {
				<-cancelDone
			}
		}()
		deadline, _ := ctx.Deadline()
		if conn.SetDeadline(deadline) != nil {
			return nil, ErrScopeUnavailable
		}
		secure := tls.Client(conn, selectedConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		var answer *dns.Msg
		if endpoint == nil {
			stream := &dns.Conn{Conn: secure}
			if _, err := stream.Write(wire); err != nil {
				return nil, err
			}
			for {
				reply, err := stream.ReadMsgHeader(nil)
				if err != nil {
					return nil, err
				}
				answer = new(dns.Msg)
				if err := answer.Unpack(reply); err != nil {
					return nil, err
				}
				if matches(request, answer) {
					break
				}
			}
		} else {
			target := *endpoint
			method := "POST"
			var body io.Reader = bytes.NewReader(wire)
			if get {
				method, body = "GET", nil
				values := target.Query()
				values.Set("dns", base64.RawURLEncoding.EncodeToString(wire))
				target.RawQuery = values.Encode()
			}
			query, err := http.NewRequestWithContext(ctx, method, target.String(), body)
			if err != nil {
				return nil, err
			}
			query.Close = true
			query.Header.Set("Accept", "application/dns-message")
			if !get {
				query.Header.Set("Content-Type", "application/dns-message")
			}
			if err := query.Write(secure); err != nil {
				return nil, err
			}
			// Bound BOTH header allocation and decoded message size. Never
			// follow Location, decompress a body or open a second connection.
			response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(secure, 98*1024)), query)
			if err != nil {
				return nil, err
			}
			defer func() { _ = conn.Close(); _ = response.Body.Close() }()
			kind, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
			if err != nil || kind != "application/dns-message" || response.StatusCode != 200 ||
				response.ContentLength > 65535 || response.Header.Get("Content-Encoding") != "" {
				return nil, ErrScopeUnavailable
			}
			reply, err := io.ReadAll(io.LimitReader(response.Body, 65536))
			if err != nil || len(reply) > 65535 {
				return nil, ErrScopeUnavailable
			}
			answer = new(dns.Msg)
			if err := answer.Unpack(reply); err != nil || !matches(request, answer) {
				return nil, ErrScopeUnavailable
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return answer, nil
	}, nil
}
