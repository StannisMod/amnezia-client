//go:build linux && !android

// Package desktop owns an OS packet tunnel inside the privileged Amnezia
// service's child process. It never runs beside a legacy AWG packet reader.
package desktop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/mobile"
	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

const InterfaceName = "amnrouting0"
const routeTable = 20313
const rulePriority = 1 // after the kernel local table, before native policy
const socketMark = uint32(0x40000000)

type Session struct {
	core      *mobile.Session
	routes    []netlink.Route
	rules     []*netlink.Rule
	manageDNS bool
	once      sync.Once
}

func command(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "resolvectl", args...).Run(); err != nil {
		return errors.New("systemd-resolved link configuration failed")
	}
	return nil
}

// preflight refuses reserved-route conflicts and mark policies that would be
// altered by our exemption bit. No existing OS rule or route is overwritten.
func preflight() error {
	if _, err := net.InterfaceByName(InterfaceName); err == nil {
		return errors.New("routing interface already exists")
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			return errors.New("native policy routing inventory unavailable")
		}
		for _, r := range rules {
			if r.Priority == rulePriority || r.Table == routeTable {
				return errors.New("reserved routing rule is occupied; explicit recovery is required")
			}
			if r.MarkSet {
				mask := uint32(0xffffffff)
				if r.Mask >= 0 {
					mask = uint32(r.Mask)
				}
				if mask&socketMark != 0 {
					return errors.New("native mark policy uses the reserved VPN exemption bit")
				}
			}
		}
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: routeTable}, netlink.RT_FILTER_TABLE)
		if err != nil || len(routes) != 0 {
			return errors.New("reserved routing table is occupied; explicit recovery is required")
		}
	}
	return nil
}

// Recover is invoked only by an explicit service stop/restart while holding
// the helper's exclusive ownership lock. Never flush an arbitrary route table.
func Recover() error {
	if _, err := net.InterfaceByName(InterfaceName); err == nil {
		return errors.New("cannot recover a live routing interface")
	}
	var ownedRules []*netlink.Rule
	var ownedRoutes []netlink.Route
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			return err
		}
		for _, r := range rules {
			if r.Table != routeTable && r.Priority != rulePriority {
				continue
			}
			legacy := r.Mark == socketMark && r.Invert && (r.IifName == "" || r.IifName == "lo")
			current := r.Mark == 0 && !r.Invert && r.IifName == "lo"
			if r.Table != routeTable || r.Priority != rulePriority || !r.MarkSet || r.Mask != int(socketMark) || (!legacy && !current) {
				return errors.New("refusing recovery of an unrecognized policy rule")
			}
			copy := r
			ownedRules = append(ownedRules, &copy)
		}
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: routeTable}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, r := range routes {
			prefix := 0
			if r.Dst != nil {
				prefix, _ = r.Dst.Mask.Size()
			}
			if r.Type != unix.RTN_BLACKHOLE || r.Priority != 32760 || r.Protocol != unix.RTPROT_STATIC || prefix != 0 {
				return errors.New("refusing recovery of an unrecognized routing entry")
			}
			ownedRoutes = append(ownedRoutes, r)
		}
	}
	for _, r := range ownedRules {
		if err := netlink.RuleDel(r); err != nil {
			return err
		}
	}
	for _, r := range ownedRoutes {
		if err := netlink.RouteDel(&r); err != nil {
			return err
		}
	}
	return nil
}

func Start(ctx context.Context, raw []byte, manageDNS bool) (*Session, error) {
	if err := preflight(); err != nil {
		return nil, err
	}
	if manageDNS {
		if err := command(ctx, "status"); err != nil {
			return nil, err
		}
	}
	s := &Session{manageDNS: manageDNS}
	hooks := mobile.Hooks{
		Protect: func(fd int) error { return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(socketMark)) },
		Interfaces: func() ([]adapter.NetworkInterface, error) {
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
					p, err := netip.ParsePrefix(address.String())
					if err == nil {
						prefixes = append(prefixes, p)
					}
				}
				result = append(result, adapter.NetworkInterface{Interface: control.Interface{Index: row.Index, Name: row.Name, MTU: row.MTU, Flags: row.Flags, Addresses: prefixes}})
			}
			return result, nil
		},
		Open: func(opts *tun.Options) (tun.Tun, error) {
			opts.FileDescriptor = 0
			opts.Name = InterfaceName
			opts.AutoRoute = false
			opts.EXP_ExternalConfiguration = true // this owner installs only tracked OS state
			t, err := tun.New(*opts)
			if err != nil {
				return nil, errors.New("native TUN creation failed")
			}
			link, err := netlink.LinkByName(InterfaceName)
			if err != nil {
				t.Close()
				return nil, err
			}
			// Only our TUN needs loose reverse-path checking for proxied replies.
			// Existing physical-interface rp_filter policy is left untouched.
			if err = os.WriteFile("/proc/sys/net/ipv4/conf/"+InterfaceName+"/rp_filter", []byte("2"), 0600); err != nil {
				t.Close()
				return nil, errors.New("capture reverse-path configuration failed")
			}
			for _, p := range append(opts.Inet4Address, opts.Inet6Address...) {
				address, err := netlink.ParseAddr(p.String())
				if err != nil {
					t.Close()
					return nil, err
				}
				if err = netlink.AddrAdd(link, address); err != nil {
					t.Close()
					return nil, err
				}
			}
			return t, nil
		},
	}
	platform, err := mobile.New(-1, hooks)
	if err != nil {
		return nil, err
	}
	s.core, err = mobile.Start(ctx, platform, raw)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	link, err := netlink.LinkByName(InterfaceName)
	if err != nil {
		return nil, err
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		// If the helper crashes, its kernel TUN disappears. The lower-priority
		prefix := "0.0.0.0/0"
		if family == unix.AF_INET6 {
			prefix = "::/0"
		}
		_, destination, _ := net.ParseCIDR(prefix)
		// blackhole stays in the owned table, so captured traffic fails closed.
		for _, route := range []netlink.Route{
			{Family: family, Dst: destination, Table: routeTable, Type: unix.RTN_BLACKHOLE, Priority: 32760, Protocol: unix.RTPROT_STATIC},
			{Family: family, Dst: destination, Table: routeTable, Type: unix.RTN_UNICAST, LinkIndex: link.Attrs().Index, Scope: netlink.SCOPE_LINK, Priority: 1, Protocol: unix.RTPROT_STATIC},
		} {
			if err := netlink.RouteAdd(&route); err != nil {
				return nil, fmt.Errorf("capture route installation failed (family %d, type %d): %w", family, route.Type, err)
			}
			s.routes = append(s.routes, route)
		}
		r := netlink.NewRule()
		r.Family = family
		r.IifName = "lo" // locally originated traffic; preserve native input/rp_filter lookups
		r.Priority = rulePriority
		r.Table = routeTable
		// Match a clear exemption bit directly. Invert would negate the whole
		// selector (including iif lo), incorrectly capturing native input too.
		r.Mark = 0
		r.MarkSet = true
		r.Mask = int(socketMark)
		if err := netlink.RuleAdd(r); err != nil {
			return nil, errors.New("capture policy installation failed")
		}
		s.rules = append(s.rules, r)
	}
	if manageDNS {
		for _, args := range [][]string{{"dns", InterfaceName, "172.19.0.2"}, {"domain", InterfaceName, "~."}, {"default-route", InterfaceName, "yes"}} {
			if err := command(ctx, args...); err != nil {
				return nil, err
			}
		}
	}
	ok = true
	return s, nil
}

func (s *Session) Stats() (awg.Stats, error) { return s.core.Stats() }

func (s *Session) Close() error {
	var errs []error
	s.once.Do(func() {
		if s.manageDNS {
			errs = append(errs, command(context.Background(), "revert", InterfaceName))
		}
		if s.core != nil {
			errs = append(errs, s.core.Close())
		}
		// Do not remove native policies or flush shared tables. These exact
		// entries were added by this successful/partially-started session only.
		for i := len(s.rules) - 1; i >= 0; i-- {
			errs = append(errs, netlink.RuleDel(s.rules[i]))
		}
		for i := len(s.routes) - 1; i >= 0; i-- {
			err := netlink.RouteDel(&s.routes[i])
			if !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENODEV) {
				errs = append(errs, err)
			}
		}
	})
	return errors.Join(errs...)
}
