package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sync"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/tunnel"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

type Session struct {
	core             *engine.Runtime
	platform         *Platform
	once             sync.Once
	closeErr         error
	networkDNSConfig []byte
}

func (s *Session) Stats() (tunnel.Stats, error) {
	if err := s.platform.CaptureError(); err != nil {
		return tunnel.Stats{}, err
	}
	return s.core.Stats()
}
func (s *Session) Diagnostics() engine.DiagnosticSnapshot      { return s.core.Diagnostics() }
func (s *Session) RefreshUnderlay(remote netip.AddrPort) error { return s.core.RefreshUnderlay(remote) }
func (s *Session) ProbeUnderlay() error                        { return s.core.ProbeUnderlay() }

// Start consumes the platform and closes it on every failed-start path. No
// fallback to the legacy backend is allowed once a routed session is requested.
func Start(ctx context.Context, p *Platform, raw []byte) (*Session, error) {
	return start(ctx, p, raw, false)
}

// StartWithNetworkDNS allows native owners to retire DNS generations
// independently of the packet tunnel and its established TCP streams.
func StartWithNetworkDNS(ctx context.Context, p *Platform, raw []byte) (*Session, error) {
	return start(ctx, p, raw, true)
}

func start(ctx context.Context, p *Platform, raw []byte, networkDNS bool) (*Session, error) {
	if p == nil {
		return nil, errors.New("missing native platform")
	}
	ok := false
	defer func() {
		if !ok {
			p.Close()
		}
	}()
	compiled, cachePath, err := compileSession(raw)
	if err != nil {
		return nil, err
	}
	ctx = engine.Context(ctx, p.Underlay())
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, p)
	startRuntime := engine.StartRuntime
	if networkDNS {
		startRuntime = engine.StartRuntimeWithNetworkDNS
	}
	instance, err := startRuntime(ctx, compiled, cachePath)
	if err != nil {
		return nil, err
	}
	ok = true
	s := &Session{core: instance, platform: p}
	if networkDNS {
		s.networkDNSConfig = append([]byte(nil), raw...)
	}
	return s, nil
}

func (s *Session) SuspendNetworkDNS() { s.core.SuspendNetworkDNS() }
func (s *Session) ReloadNetworkDNS(snapshot dnspolicy.NetworkSnapshot) error {
	// Retire before validating/preparing: an unavailable inventory must never
	// revive the previous network's cached answers or interface-bound sockets.
	return s.core.UpdateNetworkDNS(func() ([]byte, error) {
		if s.networkDNSConfig == nil {
			return nil, errors.New("native DNS reload unavailable")
		}
		compiled, _, err := compileSessionSnapshot(s.networkDNSConfig, &snapshot)
		return compiled, err
	})
}
func (s *Session) Close() error {
	s.once.Do(func() {
		s.closeErr = s.core.Close()
		if err := s.platform.Close(); s.closeErr == nil {
			s.closeErr = err
		}
	})
	return s.closeErr
}

// Validate checks the shared schema and routing compiler without opening a
// capture interface, touching the cache or creating any protected sockets.
// Android uses it before Builder.establish; Start repeats it defensively.
func Validate(raw []byte) error { _, _, err := compileSession(raw); return err }

func compileSession(raw []byte) ([]byte, string, error) {
	return compileSessionSnapshot(raw, nil)
}
func compileSessionSnapshot(raw []byte, snapshot *dnspolicy.NetworkSnapshot) ([]byte, string, error) {
	if len(raw) > 4<<20 {
		return nil, "", errors.New("routing configuration exceeds size limit")
	}
	var config struct {
		engine.SessionConfig
		CachePath string `json:"cache_path,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, "", errors.New("invalid routing session configuration")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, "", errors.New("invalid trailing routing configuration")
	}
	if config.DNS != nil && config.DNS.NeedsNetwork() {
		if snapshot != nil {
			config.NetworkDNS = snapshot
		}
		if config.NetworkDNS == nil {
			return nil, "", errors.New("native network DNS snapshot is required")
		}
		prepared, err := config.NetworkDNS.Prepare(*config.DNS)
		if err != nil {
			return nil, "", err
		}
		config.DNS = &prepared
	}
	compiled, err := config.Compile()
	return compiled, config.CachePath, err
}
