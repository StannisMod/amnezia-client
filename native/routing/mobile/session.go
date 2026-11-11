package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/tunnel"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

type Session struct {
	core                  *engine.Runtime
	platform              *Platform
	once                  sync.Once
	closeErr              error
	dnsMu                 sync.Mutex
	networkDNSUnavailable bool
	networkDNSConfig      []byte
}

func (s *Session) Stats() (tunnel.Stats, error) {
	if err := s.platform.CaptureError(); err != nil {
		return tunnel.Stats{}, err
	}
	return s.core.Stats()
}

// ReplaceCapture consumes a newly established capture descriptor, including
// when the session is stopped or its capture implementation cannot hand over.
// It changes no addresses, transport, DNS generation or routing policy.
func (s *Session) ReplaceCapture(fd int) error {
	if fd <= 0 {
		return errors.New("invalid replacement capture descriptor")
	}
	p := s.platform
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		closeDescriptor(fd)
		return net.ErrClosed
	}
	if capture, ok := p.capture.(interface{ replaceDescriptor(int) error }); ok {
		return capture.replaceDescriptor(fd)
	}
	closeDescriptor(fd)
	return unsupported
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

func (s *Session) SuspendNetworkDNS() {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	s.networkDNSUnavailable = true
	s.core.SuspendNetworkDNS()
}
func (s *Session) ReloadNetworkDNS(snapshot dnspolicy.NetworkSnapshot) error {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	s.networkDNSUnavailable = true
	var next []byte
	err := s.core.UpdateNetworkDNS(func() ([]byte, error) {
		if s.networkDNSConfig == nil {
			return nil, errors.New("native DNS reload unavailable")
		}
		var config map[string]json.RawMessage
		if err := json.Unmarshal(s.networkDNSConfig, &config); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			return nil, err
		}
		config["network_dns"] = encoded
		next, err = json.Marshal(config)
		if err != nil {
			return nil, err
		}
		compiled, _, err := compileSession(next)
		return compiled, err
	})
	if err == nil {
		s.networkDNSConfig = next
		s.networkDNSUnavailable = false
	}
	return err
}

// The native host resolves package names afresh and supplies only UID policy.
// Capture/transport/destination settings cannot be changed through this entry.
func (s *Session) UpdateAndroidApplications(raw []byte) error {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	if s.networkDNSConfig == nil || s.networkDNSUnavailable {
		return errors.New("application update requires current DNS")
	}
	if len(raw) > 65536 {
		return errors.New("application policy too large")
	}
	var apps engine.AndroidApplications
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&apps); err != nil {
		return errors.New("invalid application policy")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("invalid trailing application policy")
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(s.networkDNSConfig, &config); err != nil {
		return err
	}
	encoded, err := json.Marshal(apps)
	if err != nil {
		return err
	}
	config["android_applications"] = encoded
	next, err := json.Marshal(config)
	if err != nil {
		return err
	}
	compiled, _, err := compileSession(next)
	if err != nil {
		return err
	}
	if err = s.core.UpdateAndroidApplications(compiled); err != nil {
		return err
	}
	s.networkDNSConfig = next
	return nil
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
