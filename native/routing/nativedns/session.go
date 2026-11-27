package nativedns

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
)

// Binding retains one resolver occurrence. Never deduplicate or silently pick
// another upstream: the OS retains its original order/selection using distinct
// assigned local endpoints. Alias creation and OS settings are host-owned.
type Binding struct {
	Endpoint       netip.AddrPort `json:"endpoint"`
	Upstream       netip.AddrPort `json:"upstream"`
	InterfaceName  string         `json:"interface_name"`
	InterfaceIndex int            `json:"interface_index"`
	Transport      string         `json:"transport,omitempty"`
	ServerName     string         `json:"server_name,omitempty"`
	HTTPSURL       string         `json:"https_url,omitempty"`
}

type Config struct {
	Bindings []Binding `json:"bindings"`
}

func ParseConfig(raw string) (Config, error) {
	var config Config
	if len(raw) == 0 || len(raw) > 65536 {
		return config, ErrScopeUnavailable
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		return Config{}, ErrScopeUnavailable
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return Config{}, ErrScopeUnavailable
	}
	return config, nil
}

type Session struct {
	ctx       context.Context
	cancel    context.CancelFunc
	frontends []*SocketFrontend
	once      sync.Once
}

func (s *Session) Quiesce() {
	// Stop admission everywhere before waiting on any individual resolver.
	for _, frontend := range s.frontends {
		frontend.quiesceBegin()
	}
	for _, frontend := range s.frontends {
		frontend.forwardDone.Wait()
	}
}

// Start prepares every listener before returning success. The host must publish
// endpoint DNS settings only after success, restore those settings before Close,
// and cancel the native connection if Done closes unexpectedly. This package
// creates no aliases, routes, resolver settings or alternative VPN data path.
func Start(parent context.Context, config Config) (*Session, error) {
	if parent == nil || parent.Err() != nil || len(config.Bindings) == 0 || len(config.Bindings) > 16 {
		return nil, ErrScopeUnavailable
	}
	seen := make(map[netip.AddrPort]bool)
	for _, binding := range config.Bindings {
		if !binding.Endpoint.IsValid() || !binding.Endpoint.Addr().Is4() ||
			binding.Endpoint.Port() != 53 || seen[binding.Endpoint] {
			return nil, ErrScopeUnavailable
		}
		seen[binding.Endpoint] = true
	}
	for _, binding := range config.Bindings {
		if seen[binding.Upstream] {
			return nil, ErrScopeUnavailable
		}
	}
	ctx, cancel := context.WithCancel(parent)
	session := &Session{ctx: ctx, cancel: cancel}
	fail := func() (*Session, error) { _ = session.Close(); return nil, ErrScopeUnavailable }
	for _, binding := range config.Bindings {
		dial, err := InterfaceDial(binding.InterfaceName, binding.InterfaceIndex)
		if err != nil {
			return fail()
		}
		exchange, err := SelectedResolver(EncryptedServer{Address: binding.Upstream,
			Transport: binding.Transport, ServerName: binding.ServerName, HTTPSURL: binding.HTTPSURL}, dial, nil)
		if err != nil {
			return fail()
		}
		tcp, err := net.Listen("tcp4", binding.Endpoint.String())
		if err != nil {
			return fail()
		}
		udp, err := net.ListenPacket("udp4", binding.Endpoint.String())
		if err != nil {
			_ = tcp.Close()
			return fail()
		}
		frontend, err := NewSocket(ctx, udp, tcp, exchange)
		if err != nil {
			return fail()
		}
		session.frontends = append(session.frontends, frontend)
	}
	for _, frontend := range session.frontends {
		go func(f *SocketFrontend) {
			<-f.Done()
			cancel()
		}(frontend)
	}
	if ctx.Err() != nil {
		return fail()
	}
	go func() { <-ctx.Done(); _ = session.Close() }()
	return session, nil
}

func (s *Session) Done() <-chan struct{} { return s.ctx.Done() }
func (s *Session) Close() error {
	s.once.Do(func() {
		s.cancel()
		for _, frontend := range s.frontends {
			_ = frontend.Close()
		}
	})
	return nil
}
