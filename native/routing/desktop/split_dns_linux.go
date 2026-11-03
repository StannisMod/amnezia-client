//go:build linux && !android

package desktop

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"syscall"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

type networkDNSServer struct {
	Index   int32
	Family  int32
	Address []byte
}
type networkDNSDomain struct {
	Index       int32
	Name        string
	RoutingOnly bool
}
type networkDNSLink struct {
	Index        int32
	Name         string
	Servers      []netip.Addr
	Domains      []string
	DefaultRoute bool
}

// Read only the original links. Our own link must never enter a subsequent
// snapshot, or changes made by the VPN would appear to be changes of uplink.
func networkDNSInventory(ctx context.Context, conn *dbus.Conn) ([]networkDNSLink, error) {
	manager := conn.Object(resolvedService, "/org/freedesktop/resolve1")
	var properties map[string]dbus.Variant
	if err := manager.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, resolvedManager).Store(&properties); err != nil {
		return nil, errors.New("native network DNS inventory unavailable")
	}
	var servers []networkDNSServer
	var domains []networkDNSDomain
	if err := properties["DNS"].Store(&servers); err != nil {
		return nil, errors.New("native DNS server inventory unavailable")
	}
	if err := properties["Domains"].Store(&domains); err != nil {
		return nil, errors.New("native DNS domain inventory unavailable")
	}
	links := map[int32]*networkDNSLink{}
	for _, d := range domains {
		if d.Index <= 0 || d.Name == "." {
			continue
		}
		iface, err := net.InterfaceByIndex(int(d.Index))
		if err != nil || iface.Name == InterfaceName || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name, err := rules.NormalizeDomain(d.Name)
		if err != nil {
			return nil, errors.New("native network has an unsupported DNS routing domain")
		}
		if links[d.Index] == nil {
			links[d.Index] = &networkDNSLink{Index: d.Index, Name: iface.Name}
		}
		links[d.Index].Domains = append(links[d.Index].Domains, name)
	}
	for _, s := range servers {
		link := links[s.Index]
		if link == nil {
			iface, err := net.InterfaceByIndex(int(s.Index))
			if err != nil || s.Index <= 0 || iface.Name == InterfaceName || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			link = &networkDNSLink{Index: s.Index, Name: iface.Name}
			links[s.Index] = link
		}
		a, ok := netip.AddrFromSlice(s.Address)
		if !ok || a.IsLoopback() {
			continue
		}
		a = a.Unmap()
		if err := dnspolicy.CheckAddress(a, rules.Direct); err != nil {
			continue
		}
		link.Servers = append(link.Servers, a)
	}
	var result []networkDNSLink
	for _, link := range links {
		if len(link.Servers) == 0 {
			if len(link.Domains) > 0 {
				return nil, errors.New("corporate DNS domain has no usable native DNS server")
			}
			continue
		}
		var path dbus.ObjectPath
		var property dbus.Variant
		if err := manager.CallWithContext(ctx, resolvedManager+".GetLink", 0, link.Index).Store(&path); err != nil {
			return nil, errors.New("native DNS link inventory changed")
		}
		if err := conn.Object(resolvedService, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, resolvedInterface, "DefaultRoute").Store(&property); err != nil {
			return nil, errors.New("native DNS default route unavailable")
		}
		if err := property.Store(&link.DefaultRoute); err != nil {
			return nil, errors.New("native DNS default route unavailable")
		}
		sort.Strings(link.Domains)
		result = append(result, *link)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Index < result[j].Index })
	return result, nil
}

func networkDNSFingerprint(links []networkDNSLink) string {
	raw, _ := json.Marshal(links)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func addNetworkDNS(config *dnspolicy.Config, links []networkDNSLink) error {
	seen := map[string]string{}
	config.NetworkRules = nil
	for _, link := range links {
		if len(link.Domains) == 0 {
			continue
		}
		id := fmt.Sprintf("network-%d", link.Index)
		if _, exists := config.Policies[id]; exists {
			return errors.New("DNS policy identifier is reserved by a network interface")
		}
		// Deliberately use one server. A secondary server is not implicitly a
		// fallback policy, and simultaneous multi-link queries may leak names.
		config.Policies[id] = dnspolicy.Resolver{Name: "Network DNS", Transport: "udp", Server: link.Servers[0].String(), Path: rules.Direct, Interface: link.Name}
		for _, domain := range link.Domains {
			if previous, exists := seen[domain]; exists {
				if previous != id {
					return errors.New("corporate DNS domain belongs to multiple interfaces; configure explicit DNS exceptions and disable automatic domains")
				}
				continue
			}
			seen[domain] = id
			config.NetworkRules = append(config.NetworkRules, dnspolicy.Rule{Kind: rules.Suffix, Value: domain, Policy: id})
		}
	}
	config.PreserveNetworkDomains = false
	return nil
}

func prepareNetworkDNS(config *engine.SessionConfig) error {
	if config.DNS == nil || !config.DNS.NeedsNetwork() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return errors.New("native network DNS bus unavailable")
	}
	defer conn.Close()
	links, err := networkDNSInventory(ctx, conn)
	if err != nil {
		return err
	}
	if err = bindNetworkDNS(config.DNS, links); err != nil {
		return err
	}
	if config.DNS.PreserveNetworkDomains {
		if err = addNetworkDNS(config.DNS, links); err != nil {
			return err
		}
	}
	config.DNSNetworkFingerprint = networkDNSFingerprint(links)
	return nil
}

func bindNetworkDNS(config *dnspolicy.Config, links []networkDNSLink) error {
	for id, p := range config.Policies {
		if p.Source != "network" {
			continue
		}
		var candidates []networkDNSLink
		for _, link := range links {
			if p.Interface != "" && link.Name == p.Interface || p.Interface == "" && link.DefaultRoute {
				candidates = append(candidates, link)
			}
		}
		if len(candidates) != 1 {
			return errors.New("network DNS is missing or ambiguous; select a network interface or enter a numeric DNS server")
		}
		selected := candidates[0]
		p.Source = ""
		p.Interface = selected.Name
		p.Server = selected.Servers[0].String()
		config.Policies[id] = p
	}
	return nil
}

// Ordinary DIRECT keeps destination-based routing. Only a DNS policy explicitly
// scoped to a network interface binds its protected sockets to that interface.
func linuxUnderlay(iface string) (engine.Underlay, error) {
	if iface != "" {
		if _, err := net.InterfaceByName(iface); err != nil {
			return engine.Underlay{}, errors.New("DNS network interface is unavailable")
		}
	}
	control := func(_, _ string, raw syscall.RawConn) error {
		var inner error
		err := raw.Control(func(fd uintptr) {
			inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(socketMark))
			if inner == nil && iface != "" {
				inner = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}
		})
		if err != nil {
			return err
		}
		return inner
	}
	dial := &net.Dialer{Control: control}
	listen := &net.ListenConfig{Control: control}
	return engine.Underlay{DialContext: dial.DialContext, ListenPacket: listen.ListenPacket, OnInterface: linuxUnderlay}, nil
}
