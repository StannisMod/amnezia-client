//go:build windows

package desktop

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func windowsAdapters() ([]byte, error) {
	var size uint32 = 32 << 10
	for attempt := 0; attempt < 4; attempt++ {
		if size > 16<<20 {
			return nil, errors.New("native adapter inventory exceeds limit")
		}
		buffer := make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])), &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, errors.New("native DNS adapter inventory unavailable")
		}
		return buffer, nil
	}
	return nil, errors.New("native DNS adapter inventory changed repeatedly")
}

func windowsDNSPolicyVersion() (string, error) {
	var entries []string
	var walk func(registry.Key, string, int) error
	walk = func(key registry.Key, path string, depth int) error {
		if len(entries) > 8192 {
			return errors.New("DNS policy inventory exceeds limit")
		}
		info, err := key.Stat()
		if err != nil {
			return err
		}
		entries = append(entries, path+info.ModTime().UTC().Format(time.RFC3339Nano))
		if depth == 0 {
			return nil
		}
		names, err := key.ReadSubKeyNames(-1)
		if err != nil {
			return err
		}
		for _, name := range names {
			child, e := registry.OpenKey(key, name, registry.READ)
			if e != nil {
				return e
			}
			e = walk(child, path+"/"+name, depth-1)
			child.Close()
			if e != nil {
				return e
			}
		}
		return nil
	}
	for _, path := range []string{`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`, `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`, `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers`, `SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters`} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err == registry.ErrNotExist {
			continue
		}
		if err != nil {
			return "", errors.New("native DNS policy inventory unavailable")
		}
		err = walk(key, path, 3)
		key.Close()
		if err != nil {
			return "", err
		}
	}
	sort.Strings(entries)
	raw, _ := json.Marshal(entries)
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func addWindowsNRPT(snapshot *dnspolicy.NetworkSnapshot) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// Fixed, read-only command. No profile/domain text is interpolated into code.
	script := `[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; @((Get-DnsClientNrptPolicy -Effective) | ForEach-Object { [pscustomobject]@{ namespaces=@($_.Namespace); servers=@($_.NameServers -split '[;,\s]+' | Where-Object { $_ }); secure=[bool]($_.DnsSecValidationRequired -or $_.DnsSecQueryIPsecRequired -or $_.DirectAccessQueryIPsecRequired -or $_.DirectAccessEnabled -or $_.DirectAccessDnsServers) } }) | ConvertTo-Json -Compress -Depth 4`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	raw, err := cmd.Output()
	if err != nil || len(raw) > 4<<20 {
		return errors.New("effective Windows DNS routing policies unavailable")
	}
	raw = []byte(strings.TrimPrefix(strings.TrimSpace(string(raw)), "\ufeff"))
	var records []struct {
		Namespaces []string `json:"namespaces"`
		Servers    []string `json:"servers"`
		Secure     bool     `json:"secure"`
	}
	if len(raw) > 0 && string(raw) != "null" {
		if raw[0] == '{' {
			raw = append(append([]byte{'['}, raw...), ']')
		}
		if json.Unmarshal(raw, &records) != nil {
			return errors.New("invalid effective Windows DNS routing policies")
		}
	}
	for i, record := range records {
		if record.Secure {
			return errors.New("DNSSEC/IPsec NRPT rules require explicit supported DNS configuration")
		}
		link := dnspolicy.NetworkLink{ID: fmt.Sprintf("nrpt-%d", i)}
		for _, server := range record.Servers {
			address, e := netip.ParseAddr(server)
			if e != nil {
				return errors.New("NRPT DNS servers must be numeric")
			}
			link.Servers = append(link.Servers, dnspolicy.NetworkServer{Address: address})
		}
		if len(link.Servers) == 0 {
			for _, native := range snapshot.Links {
				if native.Default {
					link.Servers = native.Servers
					link.Interface = native.Interface
				}
			}
		}
		if len(link.Servers) == 0 {
			return errors.New("NRPT exception has no native default DNS server")
		}
		for _, namespace := range record.Namespaces {
			kind := rules.Domain
			if strings.HasPrefix(namespace, ".") {
				kind = rules.Suffix
				namespace = strings.TrimPrefix(namespace, ".")
			}
			if namespace == "" {
				return errors.New("root NRPT policy requires explicit DNS policy selection")
			}
			link.RoutingRules = append(link.RoutingRules, dnspolicy.NetworkDomain{Kind: kind, Value: namespace})
		}
		snapshot.Links = append(snapshot.Links, link)
	}
	snapshot.RoutingDomainsAvailable = true
	return nil
}

func windowsNetworkDNS() (dnspolicy.NetworkSnapshot, error) {
	storage, err := windowsAdapters()
	if err != nil {
		return dnspolicy.NetworkSnapshot{}, err
	}
	routes, err := routeTable()
	if err != nil {
		return dnspolicy.NetworkSnapshot{}, err
	}
	snapshot := dnspolicy.NetworkSnapshot{}
	bestMetric := uint64(^uint64(0))
	best := -1
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&storage[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || strings.EqualFold(windows.UTF16PtrToString(a.FriendlyName), InterfaceName) {
			continue
		}
		link := dnspolicy.NetworkLink{ID: dnspolicy.NetworkID(a.Luid), Interface: fmt.Sprintf("win:%d", a.Luid), Name: windows.UTF16PtrToString(a.FriendlyName)}
		for server := a.FirstDnsServerAddress; server != nil; server = server.Next {
			address, ok := netip.AddrFromSlice(server.Address.IP())
			if !ok || address.IsLoopback() {
				continue
			}
			address = address.Unmap()
			if address.Is6() && address.IsLinkLocalUnicast() {
				address = address.WithZone(strconv.FormatUint(uint64(a.Ipv6IfIndex), 10))
			}
			if dnspolicy.CheckAddress(address, rules.Direct) != nil {
				continue
			}
			link.Servers = append(link.Servers, dnspolicy.NetworkServer{Address: address})
		}
		if len(link.Servers) == 0 {
			continue
		}
		if suffix := windows.UTF16PtrToString(a.DnsSuffix); suffix != "" {
			link.SearchDomains = append(link.SearchDomains, suffix)
		}
		for _, route := range routes {
			if route.LUID != a.Luid || route.Destination.Length != 0 {
				continue
			}
			metric := a.Ipv4Metric
			if route.Destination.Address.Family == windows.AF_INET6 {
				metric = a.Ipv6Metric
			}
			total := uint64(metric) + uint64(route.Metric)
			if total < bestMetric {
				bestMetric = total
				best = len(snapshot.Links)
			} else if total == bestMetric && best != len(snapshot.Links) {
				best = -1
			}
		}
		snapshot.Links = append(snapshot.Links, link)
	}
	runtime.KeepAlive(storage)
	if best >= 0 {
		snapshot.Links[best].Default = true
	}
	sort.Slice(snapshot.Links, func(i, j int) bool { return snapshot.Links[i].ID < snapshot.Links[j].ID })
	return snapshot, nil
}

func windowsDNSFingerprint(snapshot dnspolicy.NetworkSnapshot) string {
	raw, _ := json.Marshal(snapshot)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func windowsDNSInterface(name string, ipv4 bool) (uint32, error) {
	storage, err := windowsAdapters()
	if err != nil {
		return 0, err
	}
	defer runtime.KeepAlive(storage)
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&storage[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp || strings.EqualFold(windows.UTF16PtrToString(a.FriendlyName), InterfaceName) {
			continue
		}
		if name != fmt.Sprintf("win:%d", a.Luid) && !strings.EqualFold(name, windows.UTF16PtrToString(a.FriendlyName)) {
			continue
		}
		index := a.Ipv6IfIndex
		if ipv4 {
			index = a.IfIndex
		}
		if index > 0 {
			return index, nil
		}
	}
	return 0, errors.New("DNS network interface is unavailable")
}
