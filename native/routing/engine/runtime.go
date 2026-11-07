package engine

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/StannisMod/amnezia-client/native/routing/internal/builddeps"
	"github.com/StannisMod/amnezia-client/native/routing/tunnel"
	box "github.com/sagernet/sing-box"
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
}

func StartRuntime(ctx context.Context, compiled []byte, cachePath string) (*Runtime, error) {
	if err := builddeps.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
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
	return &Runtime{box: instance, cancel: cancel, diagnostics: diagnostics}, nil
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
		s.closeErr = s.box.Close()
	})
	return s.closeErr
}

// BuildInfo exposes dependency identity without starting a routing session.
func BuildInfo() builddeps.Info { return builddeps.Source() }
