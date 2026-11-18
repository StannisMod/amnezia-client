package engine

import (
	"context"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// UDP has no delivery guarantee. The pinned transport multiplexes requests but
// does not retransmit a lost query/response. Keep the original attempt alive:
// a slow but valid response must not be discarded at the retry interval.
type retryingUDPDNS struct{ adapter.DNSTransport }

func registerRetryingUDP(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteDNSServerOptions](registry, "udp",
		func(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteDNSServerOptions) (adapter.DNSTransport, error) {
			delegate, err := transport.NewUDP(ctx, logger, tag, options)
			if err != nil {
				return nil, err
			}
			return &retryingUDPDNS{DNSTransport: delegate}, nil
		})
}

func (t *retryingUDPDNS) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if message.Opcode != mDNS.OpcodeQuery {
		return t.DNSTransport.Exchange(ctx, message)
	}
	return exchangeUDPWithRetry(ctx, message, time.Second, t.DNSTransport.Exchange)
}

func (t *retryingUDPDNS) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// Preserve the optional transport lifecycle interface across the decorator.
func (t *retryingUDPDNS) SetKeepIdleConnections(keep bool) {
	if keeper, ok := t.DNSTransport.(adapter.IdleConnectionKeeper); ok {
		keeper.SetKeepIdleConnections(keep)
	}
}

func (t *retryingUDPDNS) CloseIdleConnections() {
	if keeper, ok := t.DNSTransport.(adapter.IdleConnectionKeeper); ok {
		keeper.CloseIdleConnections()
	}
}

func exchangeUDPWithRetry(parent context.Context, message *mDNS.Msg, interval time.Duration,
	exchange func(context.Context, *mDNS.Msg) (*mDNS.Msg, error),
) (*mDNS.Msg, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	type result struct {
		message *mDNS.Msg
		err     error
	}
	const attempts = 3
	results := make(chan result, attempts)
	start := func() {
		query := message.Copy()
		go func() {
			response, err := exchange(ctx, query)
			results <- result{response, err}
		}()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	start()
	started, completed := 1, 0
	timer := time.NewTimer(interval)
	defer timer.Stop()
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case response := <-results:
			completed++
			// NXDOMAIN/NODATA and other DNS replies are authoritative results,
			// not reasons to switch resolver, path, family or policy.
			if response.err == nil {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return response.message, nil
			}
			lastErr = response.err
			if started == attempts && completed == started {
				return nil, lastErr
			}
		case <-timer.C:
			start()
			started++
			if started < attempts {
				timer.Reset(interval)
			}
		}
	}
}
