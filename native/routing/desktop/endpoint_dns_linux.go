//go:build linux && !android

package desktop

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/miekg/dns"
)

// Endpoint discovery is control-plane DNS only: never pass application names,
// use the managed TUN resolver, or populate/clear the application's FakeIP map.
// The exact configured hostname and cryptographic peer identity remain fixed.
func lookupEndpoint(ctx context.Context, host string, underlay engine.Underlay, resolver netip.AddrPort) ([]netip.Addr, error) {
	name, err := rules.NormalizeDomain(host)
	if _, e := netip.ParseAddr(host); e == nil {
		return nil, errors.New("VPN endpoint hostname must be a domain")
	}
	if err != nil || name != host {
		return nil, errors.New("invalid VPN endpoint hostname")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var result []netip.Addr
	for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
		query := new(dns.Msg)
		query.SetQuestion(dns.Fqdn(name), kind)
		var answer *dns.Msg
		for _, network := range []string{"udp", "tcp"} {
			transportCtx, transportCancel := context.WithTimeout(ctx, time.Second)
			c, e := underlay.DialContext(transportCtx, network, resolver.String())
			if e != nil {
				transportCancel()
				answer = nil
				err = e
				if network == "udp" && ctx.Err() == nil {
					continue
				}
				break
			}
			answer, _, e = (&dns.Client{Net: network, Timeout: time.Second}).ExchangeWithConnContext(transportCtx, query, &dns.Conn{Conn: c})
			c.Close()
			transportCancel()
			if e != nil {
				answer = nil
				err = e
				if network == "udp" && ctx.Err() == nil {
					continue
				}
				break
			}
			if answer == nil {
				err = errors.New("empty VPN endpoint DNS response")
				break
			}
			if answer.Truncated && network == "udp" {
				continue
			}
			validQuestion := len(answer.Question) == 1 && strings.EqualFold(answer.Question[0].Name, query.Question[0].Name) && answer.Question[0].Qtype == kind && answer.Question[0].Qclass == dns.ClassINET
			if !answer.Response || answer.Opcode != dns.OpcodeQuery || len(answer.Answer) > 128 || answer.Truncated || answer.Id != query.Id || answer.Rcode != dns.RcodeSuccess || !validQuestion {
				answer = nil
				err = errors.New("invalid VPN endpoint DNS response")
			}
			break
		}
		if answer == nil || answer.Truncated {
			continue
		}
		allowed := map[string]bool{strings.ToLower(dns.Fqdn(name)): true}
		for pass := 0; pass < 8; pass++ {
			for _, rr := range answer.Answer {
				if alias, ok := rr.(*dns.CNAME); ok && alias.Hdr.Class == dns.ClassINET && allowed[strings.ToLower(alias.Hdr.Name)] {
					allowed[strings.ToLower(alias.Target)] = true
				}
			}
		}
		for _, rr := range answer.Answer {
			if rr.Header().Class != dns.ClassINET || rr.Header().Rrtype != kind || !allowed[strings.ToLower(rr.Header().Name)] {
				continue
			}
			var address netip.Addr
			switch value := rr.(type) {
			case *dns.A:
				address, _ = netip.AddrFromSlice(value.A)
			case *dns.AAAA:
				address, _ = netip.AddrFromSlice(value.AAAA)
			}
			address = address.Unmap()
			if !address.IsValid() || dnspolicy.CheckAddress(address, rules.Direct) != nil {
				continue
			}
			duplicate := false
			for _, prior := range result {
				if prior == address {
					duplicate = true
					break
				}
			}
			if !duplicate && len(result) < 16 {
				result = append(result, address)
			}
		}
	}
	if len(result) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("VPN endpoint DNS has no usable addresses")
	}
	return result, nil
}
