//go:build windows

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
)

// Keep configured Windows DNS-over-HTTPS upgrades when importing a network
// source. Never silently turn an enabled upgrade into ordinary UDP DNS.
func addWindowsEncryptedDNS(snapshot *dnspolicy.NetworkSnapshot) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return addWindowsEncryptedDNSContext(ctx, snapshot)
}

func addWindowsEncryptedDNSContext(ctx context.Context, snapshot *dnspolicy.NetworkSnapshot) error {
	script := `[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) { @(Get-DnsClientDohServerAddress | Where-Object AutoUpgrade | Select-Object ServerAddress,DohTemplate) | ConvertTo-Json -Compress } else { '[]' }`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	raw, err := cmd.Output()
	if err != nil || len(raw) > 1<<20 {
		return errors.New("native encrypted DNS settings unavailable")
	}
	return applyWindowsEncryptedDNS(snapshot, raw)
}

func applyWindowsEncryptedDNS(snapshot *dnspolicy.NetworkSnapshot, raw []byte) error {
	raw = []byte(strings.TrimPrefix(strings.TrimSpace(string(raw)), "\ufeff"))
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] == '{' {
		raw = append(append([]byte{'['}, raw...), ']')
	}
	var settings []struct {
		ServerAddress string
		DohTemplate   string
	}
	if json.Unmarshal(raw, &settings) != nil {
		return errors.New("invalid native encrypted DNS settings")
	}
	for _, setting := range settings {
		address, e := netip.ParseAddr(setting.ServerAddress)
		if e != nil {
			return errors.New("invalid native encrypted DNS address")
		}
		text := strings.ReplaceAll(setting.DohTemplate, "{?dns}", "")
		if strings.ContainsAny(text, "{}") {
			return errors.New("unsupported system DoH template; configure explicit DNS")
		}
		template, e := url.Parse(text)
		if e != nil || template.Scheme != "https" || template.Hostname() == "" || template.User != nil || template.Fragment != "" {
			return errors.New("unsupported system DoH template; configure explicit DNS")
		}
		port := uint64(443)
		if template.Port() != "" {
			port, e = strconv.ParseUint(template.Port(), 10, 16)
			if e != nil || port == 0 {
				return errors.New("invalid system DoH port")
			}
		}
		path := template.EscapedPath()
		name := template.Hostname()
		if literal, e := netip.ParseAddr(name); e == nil {
			if literal.Unmap() != address.Unmap() {
				return errors.New("system DoH literal address does not match its server")
			}
			name = "" // Validate the certificate against the numeric server address.
		}
		if path == "" {
			path = "/dns-query"
		}
		if template.RawQuery != "" {
			path += "?" + template.RawQuery
		}
		for i := range snapshot.Links {
			for j := range snapshot.Links[i].Servers {
				server := &snapshot.Links[i].Servers[j]
				if server.Address.Unmap() == address.Unmap() {
					server.Transport = "https"
					server.Port = uint16(port)
					server.ServerName = name
					server.HTTPSPath = path
				}
			}
		}
	}
	return nil
}
