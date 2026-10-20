//go:build windows

package desktop

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/mobile"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

const InterfaceName = "AmneziaDomainRouting"

type Session struct {
	core     *mobile.Session
	underlay windowsUnderlay
	guard    *windowsGuard
	once     sync.Once
}

// Amnezia's native service restarts the entire child on network changes. Only
// RegisterMyInterface is used by the owned Windows TUN; no competing Go default
// interface monitor should bind every DIRECT destination to one default NIC.
type ownedWindowsMonitor struct{ tun.DefaultInterfaceMonitor }

func (ownedWindowsMonitor) RegisterMyInterface(string) {}
func (ownedWindowsMonitor) MyInterfaces() []string     { return []string{InterfaceName} }

func nativeInterfaces() ([]adapter.NetworkInterface, error) {
	rows, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []adapter.NetworkInterface
	for _, row := range rows {
		addresses, err := row.Addrs()
		if err != nil {
			return nil, err
		}
		var prefixes []netip.Prefix
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil {
				prefixes = append(prefixes, prefix)
			}
		}
		result = append(result, adapter.NetworkInterface{Interface: control.Interface{Index: row.Index, Name: row.Name, MTU: row.MTU, Flags: row.Flags, Addresses: prefixes}})
	}
	return result, nil
}

func Start(ctx context.Context, raw []byte, manageDNS bool) (*Session, error) {
	if err := mobile.Validate(raw); err != nil {
		return nil, err
	}
	if _, err := net.InterfaceByName(InterfaceName); err == nil {
		return nil, errors.New("routing adapter already exists; recovery is required")
	}
	rows, err := routeTable()
	if err != nil {
		return nil, err
	}
	s := new(Session)
	s.guard, err = newWindowsGuard()
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	underlay := s.underlay.factories()
	var luid uint64
	hooks := mobile.Hooks{
		// Any accidental use of a destination-less default socket path must
		// fail. DIRECT and AWG use the destination-aware factories above.
		Protect:    func(int) error { return errors.New("Windows sockets require destination-aware native protection") },
		Interfaces: nativeInterfaces, Underlay: &underlay,
		Open: func(opts *tun.Options) (tun.Tun, error) {
			opts.FileDescriptor = 0
			opts.Name = InterfaceName
			opts.EXP_ExternalConfiguration = false
			opts.AutoRoute = true
			opts.InterfaceMonitor = ownedWindowsMonitor{}
			opts.StrictRoute = true // dynamic WFP DNS guard; the helper is exempt
			opts.DNSMode = tun.DNSModeHijack
			if !manageDNS {
				opts.DNSMode = tun.DNSModeDisabled
				opts.StrictRoute = false
			}
			t, err := tun.New(*opts)
			if err != nil {
				return nil, errors.New("native Wintun adapter configuration failed")
			}
			luid = t.(*tun.NativeTun).LUID()
			if err := s.guard.allowCapture(luid); err != nil {
				t.Close()
				return nil, err
			}
			return t, nil
		},
	}
	p, err := mobile.New(-1, hooks)
	if err != nil {
		return nil, err
	}
	s.core, err = mobile.Start(ctx, p, raw)
	if err != nil {
		s.underlay.closed.Store(true)
		return nil, err
	}
	if err = captureSpecificRoutes(rows, luid); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func (s *Session) Stats() (awg.Stats, error) { return s.core.Stats() }
func (s *Session) Close() error {
	var err error
	s.once.Do(func() {
		s.underlay.closed.Store(true)
		if s.core != nil {
			err = s.core.Close()
		}
		if s.guard != nil {
			err = errors.Join(err, s.guard.close())
		}
	})
	return err
}

// The non-dynamic crash guard survives the adapter/DNS session. Keep it until
// all Wintun handles are gone, then remove only our exact private filter keys.
func Recover() error {
	for i := 0; i < 30; i++ {
		if _, err := net.InterfaceByName(InterfaceName); err != nil {
			return recoverWindowsGuard()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("routing adapter is still owned; refusing to delete a live adapter")
}
