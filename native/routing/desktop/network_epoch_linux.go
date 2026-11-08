//go:build linux && !android

package desktop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// Resolver inventory alone misses a new gateway/prefix when the DNS addresses
// and the selected VPN-server route remain unchanged. Hash native interfaces,
// routes and policy rules, excluding our own TUN/capture table. No state is
// modified or logged, and private netlink timeouts never alter global defaults.
func nativeNetworkEpoch() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	own := 0
	var entries []string
	for _, iface := range interfaces {
		if iface.Name == InterfaceName {
			own = iface.Index
			continue
		}
		addresses, e := iface.Addrs()
		if e != nil {
			return "", e
		}
		var prefixes []string
		for _, a := range addresses {
			prefixes = append(prefixes, a.String())
		}
		sort.Strings(prefixes)
		entries = append(entries, fmt.Sprintf("interface/%d/%s/%d/%d/%s", iface.Index, iface.Name, iface.Flags, iface.MTU, strings.Join(prefixes, ",")))
	}
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return "", err
	}
	defer handle.Close()
	if err = handle.SetSocketTimeout(time.Second); err != nil {
		return "", err
	}
	routes, err := handle.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return "", err
	}
	for _, route := range routes {
		if route.Table == routeTable || (own != 0 && route.LinkIndex == own) || route.Flags&unix.RTM_F_CLONED != 0 {
			continue
		}
		// String contains the nexthop/encapsulation. Add selection fields it
		// omits, and dereference MPLSDst (its String implementation prints the
		// pointer). Exclude expiry/cache statistics and cloned PMTU entries.
		mpls, hasMPLS := 0, route.MPLSDst != nil
		if hasMPLS {
			mpls = *route.MPLSDst
			route.MPLSDst = nil
		}
		entries = append(entries, fmt.Sprintf("route/%d/%d/%d/%d/%d/%d/%t/%d/%s", route.Family, route.Type, route.Protocol, route.Priority, route.Scope, route.Tos, hasMPLS, mpls, route.String()))
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := handle.RuleList(family)
		if err != nil {
			return "", err
		}
		for _, rule := range rules {
			if rule.Table == routeTable && rule.Priority == rulePriority {
				continue
			}
			data, e := json.Marshal(rule)
			if e != nil {
				return "", e
			}
			entries = append(entries, fmt.Sprintf("rule/%d/%s", family, data))
		}
	}
	sort.Strings(entries)
	digest := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(digest[:]), nil
}
