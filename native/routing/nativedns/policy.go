package nativedns

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// Exchange must retain the original resolver and scope and honor cancellation.
// This package does not provide a default dialer or choose a fallback resolver.
type Exchange func(context.Context, string, *dns.Msg) (*dns.Msg, error)

func Handler(ctx context.Context, exchange Exchange) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		var answer *dns.Msg
		if request.Opcode == dns.OpcodeQuery && len(request.Question) != 1 {
			answer = new(dns.Msg).SetRcode(request, dns.RcodeFormatError)
		} else if request.Opcode == dns.OpcodeQuery && request.Question[0].Qtype == dns.TypeAAAA {
			answer = new(dns.Msg).SetReply(request)
			answer.RecursionAvailable = true
			answer.AuthenticatedData = false
		} else {
			queryCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			var err error
			answer, err = exchange(queryCtx, w.RemoteAddr().Network(), request.Copy())
			stop()
			if err != nil || answer == nil {
				answer = new(dns.Msg).SetRcode(request, dns.RcodeServerFailure)
			} else {
				answer = answer.Copy()
				answer.Id = request.Id
			}
		}
		_ = w.WriteMsg(answer)
	})
}
