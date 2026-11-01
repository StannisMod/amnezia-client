package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

type Session struct {
	box      *box.Box
	platform *Platform
	cancel   context.CancelFunc
	once     sync.Once
}

func (s *Session) Stats() (awg.Stats, error) {
	out, ok := s.box.Outbound().Outbound("vpn")
	if !ok {
		return awg.Stats{}, errors.New("AWG outbound unavailable")
	}
	transport, ok := out.(*awg.Outbound)
	if !ok {
		return awg.Stats{}, errors.New("invalid AWG outbound")
	}
	return transport.Stats()
}

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
	ctx, cancel := context.WithCancel(ctx)
	ctx = engine.Context(ctx, p.Underlay())
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, p)
	instance, err := engine.NewWithCache(ctx, compiled, cachePath)
	if err != nil {
		cancel()
		return nil, errors.New("routing engine initialization failed")
	}
	if err = instance.Start(); err != nil {
		cancel()
		return nil, errors.New("routing engine startup failed")
	}
	ok = true
	return &Session{box: instance, platform: p, cancel: cancel}, nil
}
func (s *Session) Close() error {
	var err error
	s.once.Do(func() {
		s.cancel()
		err = s.box.Close()
		if e := s.platform.Close(); err == nil {
			err = e
		}
	})
	return err
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
