// Package dnsguard provides a DNS-only packet endpoint for native VPN adapters.
// It does not capture native traffic or choose an upstream network by itself.
package dnsguard

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/internal/builddeps"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/miekg/dns"
)

// Exchange must use the connection's selected DNS scope and honor cancellation.
// No default dialer or fallback resolver is provided.
type Exchange func(context.Context, string, *dns.Msg) (*dns.Msg, error)

type Frontend struct {
	device  tun.Device
	address netip.Addr
	ctx     context.Context
	cancel  context.CancelFunc
	udp     *dns.Server
	tcp     *dns.Server
	done    sync.WaitGroup
	once    sync.Once
}

// New creates an in-memory endpoint. The caller alone owns packet dispatch:
// deliver packets addressed to address:53 and return its output to capture.
// Other native VPN packets must not be redirected to this endpoint.
func New(parent context.Context, address netip.Addr, exchange Exchange) (*Frontend, error) {
	if parent == nil || !address.IsGlobalUnicast() || address.Zone() != "" || exchange == nil {
		return nil, errors.New("DNS guard requires a unicast capture address and scoped exchange")
	}
	if err := builddeps.Validate(); err != nil {
		return nil, err
	}
	device, stack, err := awg.NewFlowTUN([]netip.Addr{address}, 1280)
	if err != nil {
		return nil, err
	}
	udp, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(address, 53))
	if err != nil {
		device.Close()
		return nil, err
	}
	tcp, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(address, 53))
	if err != nil {
		udp.Close()
		device.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	f := &Frontend{device: device, address: address, ctx: ctx, cancel: cancel}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		var answer *dns.Msg
		if request.Opcode == dns.OpcodeQuery && len(request.Question) != 1 {
			answer = new(dns.Msg).SetRcode(request, dns.RcodeFormatError)
		} else if request.Opcode == dns.OpcodeQuery && request.Question[0].Qtype == dns.TypeAAAA {
			// Local policy is not an authenticated denial by the upstream.
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
	f.udp = &dns.Server{PacketConn: udp, Handler: handler, UDPSize: 4096,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	f.tcp = &dns.Server{Listener: tcp, Handler: handler,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxTCPQueries: 128}
	ready := make(chan struct{}, 2)
	f.udp.NotifyStartedFunc = func() { ready <- struct{}{} }
	f.tcp.NotifyStartedFunc = func() { ready <- struct{}{} }
	f.done.Add(2)
	serve := func(server *dns.Server) {
		defer f.done.Done()
		_ = server.ActivateAndServe()
		// Unexpected listener exit invalidates the whole endpoint. Native
		// adapters must observe Done and retain their fail-closed capture.
		cancel()
	}
	go serve(f.udp)
	go serve(f.tcp)
	for i := 0; i < 2; i++ {
		select {
		case <-ready:
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		}
	}
	go func() { <-ctx.Done(); _ = f.Close() }()
	return f, nil
}

// Device exposes packet I/O only; it installs no OS routes or capture reader.
func (f *Frontend) Device() tun.Device { return f.device }

func (f *Frontend) HandlesPacket(packet []byte) bool { return dnsDestination(packet, f.address) }

func (f *Frontend) Done() <-chan struct{} { return f.ctx.Done() }

func (f *Frontend) Close() error {
	f.once.Do(func() {
		f.cancel()
		// Cancel exchanges before waiting for DNS handlers to leave. Closing
		// the device also releases packet readers owned by the adapter.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.udp.ShutdownContext(ctx)
		_ = f.tcp.ShutdownContext(ctx)
		_ = f.device.Close()
		f.done.Wait()
	})
	return nil
}
