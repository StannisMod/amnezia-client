// Package mobile connects the shared engine to an app-owned packet tunnel.
// It never establishes a second VPN or changes the host's routes/resolvers.
package mobile

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
)

var unsupported = errors.New("operation is not provided by the Amnezia packet-tunnel host")

type Hooks struct {
	// Protect must exempt the socket before connect or first send. It must not
	// change the destination's native route to an arbitrary physical gateway.
	Protect    func(int) error
	Interfaces func() ([]adapter.NetworkInterface, error)
	Release    func()
	// Open is supplied by packet-flow hosts/tests. Android uses the existing FD.
	Open             func(*tun.Options) (tun.Tun, error)
	NetworkExtension bool
}

type Platform struct {
	mu     sync.RWMutex
	hooks  Hooks
	fd     int
	taken  bool
	closed bool
}

var _ adapter.PlatformInterface = (*Platform)(nil)

// New takes ownership of fd on success. The native caller retains it on error.
func New(fd int, hooks Hooks) (*Platform, error) {
	if (fd <= 0 && hooks.Open == nil) || hooks.Protect == nil || hooks.Interfaces == nil {
		return nil, errors.New("packet tunnel and native socket/interface hooks are required")
	}
	return &Platform{fd: fd, hooks: hooks}, nil
}

// Close follows engine.Close. The lock also prevents a late dial callback from
// accessing a released JNI global reference after network/worker cancellation.
func (p *Platform) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var err error
	if !p.taken && p.fd >= 0 {
		err = closeDescriptor(p.fd)
	}
	if p.hooks.Release != nil {
		p.hooks.Release()
	}
	return err
}

func (p *Platform) AutoDetectInterfaceControl(fd int) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return net.ErrClosed
	}
	return p.hooks.Protect(fd)
}
func (p *Platform) Underlay() engine.Underlay {
	control := func(_, _ string, raw syscall.RawConn) error {
		var inner error
		if err := raw.Control(func(fd uintptr) { inner = p.AutoDetectInterfaceControl(int(fd)) }); err != nil {
			return err
		}
		return inner
	}
	dial := &net.Dialer{Control: control}
	listen := &net.ListenConfig{Control: control}
	return engine.Underlay{DialContext: dial.DialContext, ListenPacket: listen.ListenPacket}
}
func (p *Platform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, net.ErrClosed
	}
	return p.hooks.Interfaces()
}
func (p *Platform) OpenInterface(opts *tun.Options, _ option.TunPlatformOptions) (tun.Tun, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, net.ErrClosed
	}
	if p.taken {
		return nil, errors.New("packet tunnel already has a reader")
	}
	opts.FileDescriptor = p.fd
	opts.AutoRoute = false
	opts.EXP_ExternalConfiguration = true
	var t tun.Tun
	var err error
	if p.hooks.Open != nil {
		t, err = p.hooks.Open(opts)
	} else {
		t, err = openDescriptor(opts)
	}
	if err == nil {
		p.taken = true
	}
	return t, err
}
func (p *Platform) Initialize(adapter.NetworkManager) error                { return nil }
func (p *Platform) UsePlatformAutoDetectInterfaceControl() bool            { return true }
func (p *Platform) UsePlatformInterface() bool                             { return true }
func (p *Platform) ProcessPlatformOptions(option.TunPlatformOptions) error { return nil }

// The existing Amnezia mobile service performs full session restart on native
// network changes. Do not create a competing Go interface-monitor lifecycle.
func (p *Platform) UsePlatformDefaultInterfaceMonitor() bool { return true }
func (p *Platform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}
func (p *Platform) UsePlatformNetworkInterfaces() bool              { return true }
func (p *Platform) UnderNetworkExtension() bool                     { return p.hooks.NetworkExtension }
func (p *Platform) NetworkExtensionIncludeAllNetworks() bool        { return false }
func (p *Platform) ClearDNSCache()                                  {}
func (p *Platform) RequestPermissionForWIFIState() error            { return unsupported }
func (p *Platform) ReadWIFIState(context.Context) adapter.WIFIState { return adapter.WIFIState{} }
func (p *Platform) UsePlatformConnectionOwnerFinder() bool          { return false }
func (p *Platform) FindConnectionOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, unsupported
}
func (p *Platform) UsePlatformWIFIMonitor() bool                              { return false }
func (p *Platform) UsePlatformNotification() bool                             { return false }
func (p *Platform) SendNotification(*adapter.Notification) error              { return unsupported }
func (p *Platform) CancelNotification(string, int32) error                    { return unsupported }
func (p *Platform) MyInterfaceAddress() []netip.Addr                          { return nil }
func (p *Platform) UsePlatformNeighborResolver() bool                         { return false }
func (p *Platform) StartNeighborMonitor(adapter.NeighborUpdateListener) error { return unsupported }
func (p *Platform) CloseNeighborMonitor(adapter.NeighborUpdateListener) error { return nil }
func (p *Platform) UsePlatformShell() bool                                    { return false }
func (p *Platform) CheckPlatformShell() error                                 { return unsupported }
func (p *Platform) OpenShellSession(*adapter.PlatformUser, string, []string, string, int32, int32) (adapter.ShellSession, error) {
	return nil, unsupported
}
func (p *Platform) LookupUser(string) (*adapter.PlatformUser, error) { return nil, unsupported }
func (p *Platform) LookupSFTPServer() (string, error)                { return "", unsupported }
func (p *Platform) ReadSystemSSHHostKey() ([]byte, error)            { return nil, unsupported }
func (p *Platform) TailscaleHostname() string                        { return "" }
func (p *Platform) UsePlatformBridge() bool                          { return false }
func (p *Platform) CreateBridge(adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, unsupported
}
