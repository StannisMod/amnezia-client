package engine

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/StannisMod/amnezia-client/native/routing/internal/builddeps"
	"github.com/StannisMod/amnezia-client/native/routing/tunnel"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

// Runtime owns engine workers for every transport. Native hosts separately own
// their capture descriptor and OS rollback, including on a failed StartRuntime.
type Runtime struct {
	box         *box.Box
	cancel      context.CancelFunc
	once        sync.Once
	closeErr    error
	diagnostics *Diagnostics
	lifecycle   sync.Mutex
	closed      bool
	dns         *networkDNSProxy
	ctx         context.Context
}

func StartRuntime(ctx context.Context, compiled []byte, cachePath string) (*Runtime, error) {
	return startRuntime(ctx, compiled, cachePath, false)
}

func StartRuntimeWithNetworkDNS(ctx context.Context, compiled []byte, cachePath string) (*Runtime, error) {
	return startRuntime(ctx, compiled, cachePath, true)
}

func startRuntime(ctx context.Context, compiled []byte, cachePath string, networkDNS bool) (*Runtime, error) {
	if err := builddeps.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	var proxy *networkDNSProxy
	if networkDNS {
		proxy = &networkDNSProxy{}
	}
	ctx = service.ContextWith[*networkDNSProxy](ctx, proxy)
	instance, err := NewWithCache(ctx, compiled, cachePath)
	if err != nil {
		cancel()
		return nil, errors.New("routing engine initialization failed")
	}
	diagnostics := new(Diagnostics)
	instance.Router().AppendTracker(diagnostics)
	if err = instance.Start(); err != nil {
		cancel()
		// The pinned Box.Start unwinds its own scope on failure.
		return nil, errors.New("routing engine startup failed")
	}
	runtime := &Runtime{box: instance, cancel: cancel, diagnostics: diagnostics, dns: proxy, ctx: ctx}
	if proxy != nil {
		version := proxy.freeze()
		generation, err := runtime.dnsGeneration(compiled)
		if err != nil {
			runtime.Close()
			return nil, err
		}
		if !proxy.replace(generation, version) {
			runtime.Close()
			return nil, errors.New("network DNS startup superseded")
		}
	}
	return runtime, nil
}

func (s *Runtime) dnsGeneration(compiled []byte) (*dnsGeneration, error) {
	host := service.FromContext[*runtimeHost](s.ctx)
	vpn, ok := s.box.Outbound().Outbound("vpn")
	if host == nil || !ok {
		return nil, errors.New("network DNS host unavailable")
	}
	return newDNSGeneration(s.ctx, compiled, host.underlay, service.FromContext[adapter.PlatformInterface](s.ctx), vpn)
}

// Freeze first, even when the replacement snapshot is invalid/unavailable.
// Neither this nor a failed reload releases established application flows.
func (s *Runtime) SuspendNetworkDNS() {
	if s.dns != nil {
		s.dns.freeze()
	}
}
func (s *Runtime) ReloadNetworkDNS(compiled []byte) error {
	return s.UpdateNetworkDNS(func() ([]byte, error) { return compiled, nil })
}

// UpdateNetworkDNS reserves the generation before native preparation. A newer
// suspension invalidates even a candidate still being compiled by the host.
func (s *Runtime) UpdateNetworkDNS(prepare func() ([]byte, error)) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed || s.dns == nil {
		return errors.New("network DNS reload unavailable")
	}
	version := s.dns.freeze()
	compiled, err := prepare()
	if err != nil {
		return err
	}
	g, err := s.dnsGeneration(compiled)
	if err != nil {
		return err
	}
	if !s.dns.replace(g, version) {
		return errors.New("network DNS reload superseded")
	}
	return nil
}
func (s *Runtime) Stats() (tunnel.Stats, error) {
	out, ok := s.box.Outbound().Outbound("vpn")
	if !ok {
		return tunnel.Stats{}, errors.New("VPN outbound unavailable")
	}
	transport, ok := out.(tunnel.Statistics)
	if !ok {
		return tunnel.Stats{}, errors.New("VPN statistics unsupported")
	}
	return transport.Stats()
}
func (s *Runtime) Diagnostics() DiagnosticSnapshot { return s.diagnostics.Snapshot() }

// RefreshUnderlay retains the Box, capture reader, route/flow ownership and
// private TCP stack. It must never call Network.ResetNetwork: that operation
// closes all tracked application connections in the pinned engine.
func (s *Runtime) RefreshUnderlay(remote netip.AddrPort) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return errors.New("routing runtime is closed")
	}
	if err := s.box.Network().UpdateInterfaces(); err != nil {
		return errors.New("native interface inventory refresh failed")
	}
	out, ok := s.box.Outbound().Outbound("vpn")
	if !ok {
		return errors.New("VPN outbound unavailable")
	}
	refresh, ok := out.(tunnel.UnderlayRefresher)
	if !ok {
		return errors.New("VPN underlay recovery unsupported")
	}
	return refresh.RefreshUnderlay(remote)
}
func (s *Runtime) Close() error {
	s.once.Do(func() {
		s.lifecycle.Lock()
		defer s.lifecycle.Unlock()
		s.closed = true
		s.cancel()
		if s.dns != nil {
			s.dns.freeze()
		}
		s.closeErr = s.box.Close()
	})
	return s.closeErr
}

// BuildInfo exposes dependency identity without starting a routing session.
func BuildInfo() builddeps.Info { return builddeps.Source() }
