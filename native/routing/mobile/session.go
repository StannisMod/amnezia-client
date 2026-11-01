package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/tunnel"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

type Session struct {
	core     *engine.Runtime
	platform *Platform
	once     sync.Once
	closeErr error
}

func (s *Session) Stats() (tunnel.Stats, error)           { return s.core.Stats() }
func (s *Session) Diagnostics() engine.DiagnosticSnapshot { return s.core.Diagnostics() }

// Start consumes the platform and closes it on every failed-start path. No
// fallback to the legacy backend is allowed once a routed session is requested.
func Start(ctx context.Context, p *Platform, raw []byte) (*Session, error) {
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
	instance, err := engine.StartRuntime(ctx, compiled, cachePath)
	if err != nil {
		return nil, err
	}
	ok = true
	return &Session{core: instance, platform: p}, nil
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
	compiled, err := config.Compile()
	return compiled, config.CachePath, err
}
