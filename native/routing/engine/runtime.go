package engine

import (
	"context"
	"errors"
	"sync"

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
}

func StartRuntime(ctx context.Context, compiled []byte, cachePath string) (*Runtime, error) {
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
func (s *Runtime) Close() error {
	s.once.Do(func() { s.cancel(); s.closeErr = s.box.Close() })
	return s.closeErr
}
