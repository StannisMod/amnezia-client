package nativedns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var ErrScopeUnavailable = errors.New("native DNS resolver scope unavailable")

// Dial must bind to the original resolver's scope. It receives only numeric
// IPv4 endpoints and an explicit tcp4/udp4 transport. There is no default dialer.
type Dial func(context.Context, string, netip.AddrPort) (net.Conn, error)

// Resolver retains exactly one originally selected server. An IPv6-only server
// remains represented, so its endpoint can answer AAAA locally, but all actual
// forwarding to it is unavailable under OFF. It is never replaced with IPv4.
func Resolver(server netip.AddrPort, dial Dial) (Exchange, error) {
	if !server.IsValid() || server.Port() == 0 || server.Addr().IsUnspecified() ||
		server.Addr().IsMulticast() || dial == nil {
		return nil, ErrScopeUnavailable
	}
	return func(parent context.Context, network string, request *dns.Msg) (*dns.Msg, error) {
		return exchangeScoped(parent, server, dial, network, request, time.Second)
	}, nil
}

func exchangeScoped(parent context.Context, server netip.AddrPort, dial Dial,
	network string, request *dns.Msg, retryInterval time.Duration) (*dns.Msg, error) {
	if parent == nil || request == nil || request.Response || !server.Addr().Is4() {
		return nil, ErrScopeUnavailable
	}
	switch network {
	case "udp", "tcp":
	default:
		return nil, ErrScopeUnavailable
	}
	request = request.Copy()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := dial(ctx, network+"4", server)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, ErrScopeUnavailable
	}
	if conn == nil {
		return nil, ErrScopeUnavailable
	}
	defer conn.Close()
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, ErrScopeUnavailable
		}
	}
	// Keep signing/authentication with the original client/server. Do not let
	// dns.Conn.WriteMsg re-sign an opaque native request with proxy credentials.
	query, err := request.Pack()
	if err != nil {
		return nil, err
	}
	stream := &dns.Conn{Conn: conn, UDPSize: 65535}
	if _, err := stream.Write(query); err != nil {
		return nil, err
	}
	type result struct {
		answer *dns.Msg
		err    error
	}
	replies, readerDone := make(chan result, 1), make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			wire, err := stream.ReadMsgHeader(nil)
			if err != nil {
				replies <- result{err: err}
				return
			}
			answer := new(dns.Msg)
			if err := answer.Unpack(wire); err != nil {
				replies <- result{err: err}
				return
			}
			if matches(request, answer) {
				replies <- result{answer: answer}
				return
			}
			// A stale/spurious reply cannot complete the transaction. Preserve
			// the same socket so an already in-flight valid slow reply survives.
		}
	}()
	defer func() { _ = conn.Close(); <-readerDone }()
	var retry <-chan time.Time
	var ticker *time.Ticker
	if network == "udp" && request.Opcode == dns.OpcodeQuery {
		ticker = time.NewTicker(retryInterval)
		defer ticker.Stop()
		retry = ticker.C
	}
	attempts := 1
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case response := <-replies:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return response.answer, response.err
		case <-retry:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if attempts >= 3 {
				retry = nil
				continue
			}
			attempts++
			if _, err := stream.Write(query); err != nil {
				return nil, err
			}
		}
	}
}

func matches(request, answer *dns.Msg) bool {
	if !answer.Response || answer.Id != request.Id || answer.Opcode != request.Opcode ||
		len(answer.Question) != len(request.Question) {
		return false
	}
	for i, question := range request.Question {
		reply := answer.Question[i]
		if question.Qtype != reply.Qtype || question.Qclass != reply.Qclass ||
			!strings.EqualFold(question.Name, reply.Name) {
			return false
		}
	}
	return true
}
