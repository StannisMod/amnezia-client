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
	Index      int32
	Family     int32
	Address    []byte
	Port       uint16
	ServerName string
}
type networkDNSDomain struct {
	Index       int32
	Name        string
	RoutingOnly bool
}
type networkDNSLink struct {
	Index        int32
	Name         string
	Servers      []dnspolicy.NetworkServer
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
	if err := properties["DNSEx"].Store(&servers); err != nil {
		return nil, errors.New("native extended DNS server inventory unavailable; configure explicit DNS policies")
	}
	var globalTLS string
	if err := properties["DNSOverTLS"].Store(&globalTLS); err != nil {
		return nil, errors.New("native DNS encryption setting unavailable")
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
		if a.Is6() && a.IsLinkLocalUnicast() {
			a = a.WithZone(link.Name)
		}
		if err := dnspolicy.CheckAddress(a, rules.Direct); err != nil {
			continue
		}
		link.Servers = append(link.Servers, dnspolicy.NetworkServer{Address: a, Port: s.Port, ServerName: s.ServerName})
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
		if err := manager.CallWithContext(ctx, resolvedManager+".GetLink", 0, link.Index).Store(&path); err != nil {
			return nil, errors.New("native DNS link inventory changed")
		}
		var linkProperties map[string]dbus.Variant
		if err := conn.Object(resolvedService, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, resolvedInterface).Store(&linkProperties); err != nil {
			return nil, errors.New("native DNS link settings unavailable")
		}
		if err := linkProperties["DefaultRoute"].Store(&link.DefaultRoute); err != nil {
			return nil, errors.New("native DNS default route unavailable")
		}
		var linkTLS string
		if err := linkProperties["DNSOverTLS"].Store(&linkTLS); err != nil {
			return nil, errors.New("native DNS link encryption setting unavailable")
		}
		for i, server := range link.Servers {
			prepared, err := networkDNSTransport(server, globalTLS, linkTLS)
			if err != nil {
				return nil, err
			}
			link.Servers[i] = prepared
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

// DNSOverTLS on a link overrides the manager setting; an empty link value
// inherits it. Opportunistic mode stays encrypted here: never retry plaintext.
func networkDNSTransport(server dnspolicy.NetworkServer, global, link string) (dnspolicy.NetworkServer, error) {
	mode := link
	if mode == "" {
		mode = global
	}
	switch mode {
	case "no":
		server.Transport = "udp"
		server.ServerName = ""
	case "yes", "opportunistic":
		server.Transport = "tls"
		server.OpportunisticTLS = mode == "opportunistic"
	default:
		return dnspolicy.NetworkServer{}, errors.New("unsupported native DNS encryption mode; configure explicit DNS policies")
	}
	return server, nil
}

func linuxDNSSnapshot(links []networkDNSLink) dnspolicy.NetworkSnapshot {
	snapshot := dnspolicy.NetworkSnapshot{RoutingDomainsAvailable: true}
	for _, link := range links {
		snapshot.Links = append(snapshot.Links, dnspolicy.NetworkLink{
			ID: dnspolicy.NetworkID(uint64(link.Index)), Interface: link.Name,
			Default: link.DefaultRoute, Servers: link.Servers, Domains: link.Domains,
		})
	}
	return snapshot
}

func addNetworkDNS(config *dnspolicy.Config, links []networkDNSLink) error {
	c := *config
	c.PreserveNetworkDomains = true
	prepared, err := linuxDNSSnapshot(links).Prepare(c)
	if err != nil {
		return err
	}
	*config = prepared
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
	c := *config
	c.PreserveNetworkDomains = false
	prepared, err := linuxDNSSnapshot(links).Prepare(c)
	if err != nil {
		return err
	}
	prepared.PreserveNetworkDomains = config.PreserveNetworkDomains
	*config = prepared
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
