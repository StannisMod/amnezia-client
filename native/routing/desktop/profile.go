package desktop

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/StannisMod/amnezia-client/native/routing/wireguard"
)

func text(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case json.Number:
		return string(v)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

// ProfileSession converts native AWG or WireGuard profiles used by the Qt client.
// No resolved legacy site addresses or raw backend configuration is accepted.
// Desktop app scope precedes domain routing; OS kill-switch integration is
// checked independently by the service.
func ProfileSession(raw []byte) (engine.SessionConfig, error) {
	var profile struct {
		Protocol  string            `json:"protocol"`
		DNS       string            `json:"dns1"`
		DNSPath   rules.Action      `json:"sing_box_dns_path"`
		SplitDNS  *dnspolicy.Config `json:"sing_box_dns"`
		Rules     rules.Config      `json:"sing_box_routing"`
		AWG       map[string]any    `json:"awg_config_data"`
		WireGuard map[string]any    `json:"wireguard_config_data"`
		AppScope  int               `json:"appSplitTunnelType"`
		Apps      []string          `json:"splitTunnelApps"`
	}
	if len(raw) > 4<<20 {
		return engine.SessionConfig{}, errors.New("routing profile exceeds size limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&profile); err != nil || (profile.Protocol != "awg" && profile.Protocol != "wireguard") {
		return engine.SessionConfig{}, errors.New("unsupported routed desktop transport")
	}
	resolver, err := netip.ParseAddr(profile.DNS)
	if err != nil && profile.SplitDNS == nil {
		return engine.SessionConfig{}, errors.New("a numeric DNS resolver is required")
	}
	config := engine.SessionConfig{Rules: profile.Rules, Resolver: netip.AddrPortFrom(resolver, 53), ResolverAction: profile.DNSPath, DNS: profile.SplitDNS}
	if profile.AppScope < 0 || profile.AppScope > 2 {
		return config, errors.New("invalid desktop application scope")
	}
	if profile.AppScope != 0 {
		mode := "include"
		if profile.AppScope == 2 {
			mode = "exclude"
		}
		paths := make([]string, 0, len(profile.Apps))
		for _, path := range profile.Apps {
			if !filepath.IsAbs(path) {
				return config, errors.New("application scope requires absolute executable paths")
			}
			// Linux desktop entries often contain symlinks; kernel ownership
			// reports the actual executable. Preserve an absent absolute path
			// for applications that may be installed after this profile is saved.
			path = filepath.Clean(path)
			if actual, err := filepath.EvalSymlinks(path); err == nil {
				path = actual
			}
			paths = append(paths, path)
		}
		config.Applications = &engine.ApplicationScope{Mode: mode, Paths: paths}
	}
	if config.ResolverAction == "" {
		config.ResolverAction = rules.VPN
	}
	if resolver.IsLoopback() {
		config.ResolverAction = rules.Direct
	}
	wg := profile.AWG
	if profile.Protocol == "wireguard" {
		wg = profile.WireGuard
	}
	if wg == nil {
		return config, errors.New("missing VPN transport profile")
	}
	if profile.Protocol == "wireguard" {
		// An obfuscated imported WG profile is AWG in wire format. Require the
		// explicit AWG adapter rather than dropping extensions silently.
		if text(wg["isObfuscationEnabled"]) == "true" {
			return config, errors.New("obfuscated WireGuard requires the AWG adapter")
		}
		for _, key := range strings.Fields("Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies") {
			if text(wg[key]) != "" {
				return config, errors.New("AWG parameters require the AWG adapter")
			}
		}
	}
	endpoint, err := netip.ParseAddr(text(wg["hostName"]))
	if err != nil {
		return config, errors.New("VPN endpoint must be bootstrapped before OS capture")
	}
	port, err := strconv.ParseUint(text(wg["port"]), 10, 16)
	if err != nil || port == 0 {
		return config, errors.New("invalid VPN endpoint port")
	}
	config.AWG = awg.Config{PrivateKey: text(wg["client_priv_key"]), PublicKey: text(wg["server_pub_key"]), PreSharedKey: text(wg["psk_key"]), Endpoint: netip.AddrPortFrom(endpoint, uint16(port)), Parameters: map[string]string{}}
	for _, input := range strings.Split(text(wg["client_ip"]), ",") {
		input = strings.TrimSpace(input)
		var a netip.Addr
		if p, err := netip.ParsePrefix(input); err == nil {
			a = p.Addr()
		} else {
			a, err = netip.ParseAddr(input)
			if err != nil {
				return config, errors.New("invalid VPN interface address")
			}
		}
		config.AWG.Address = append(config.AWG.Address, a)
	}
	allowed, ok := wg["allowed_ips"].([]any)
	if !ok {
		return config, errors.New("VPN allowed IPs must be a list")
	}
	default4 := false
	for _, value := range allowed {
		p, err := netip.ParsePrefix(text(value))
		if err != nil {
			return config, errors.New("invalid VPN allowed IP prefix")
		}
		config.AWG.AllowedIPs = append(config.AWG.AllowedIPs, p)
		default4 = default4 || p == netip.MustParsePrefix("0.0.0.0/0")
	}
	if !default4 {
		return config, errors.New("domain routing requires an IPv4 default route")
	}
	if value := text(wg["mtu"]); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return config, errors.New("invalid VPN MTU")
		}
		config.AWG.MTU = n
	}
	if value := text(wg["persistent_keep_alive"]); value != "" {
		keepalive, err := awg.ParseKeepalive(value)
		if err != nil {
			return config, errors.New("invalid VPN keepalive")
		}
		config.AWG.Keepalive = keepalive
	}
	if profile.Protocol == "awg" {
		for _, key := range strings.Fields("Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5") {
			if value := text(wg[key]); value != "" {
				config.AWG.Parameters[strings.ToLower(key)] = value
			}
		}
		for input, output := range map[string]string{"HeaderProtectionKey": "header_protection_key", "ContentPaddingAddition": "content_padding_addition", "RekeyAfterTime": "rekey_after_time", "RekeyTimeout": "rekey_timeout", "RejectAfterTime": "reject_after_time", "KeepaliveTimeout": "keepalive_timeout", "MaxHandshakeAttempts": "max_handshake_attempts", "RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies"} {
			value := text(wg[input])
			if value == "" {
				continue
			}
			if input == "HeaderProtectionKey" {
				key, err := base64.StdEncoding.DecodeString(value)
				if err != nil || len(key) != 32 {
					return config, errors.New("invalid AWG header protection key")
				}
				value = hex.EncodeToString(key)
			}
			if input == "RandomTrailers" || input == "DisableCookies" {
				switch strings.ToLower(value) {
				case "on", "true", "1":
					value = "true"
				case "off", "false", "0":
					value = "false"
				default:
					return config, errors.New("invalid AWG boolean parameter")
				}
			}
			config.AWG.Parameters[output] = value
		}
	} else {
		keepalive, err := strconv.ParseUint(config.AWG.Keepalive.String(), 10, 16)
		if err != nil {
			return config, errors.New("standard WireGuard keepalive must be 0..65535")
		}
		c := config.AWG
		config.VPN = &engine.TransportConfig{Type: "wireguard", WireGuard: &wireguard.Config{Address: c.Address, MTU: c.MTU, PrivateKey: c.PrivateKey, PublicKey: c.PublicKey, PreSharedKey: c.PreSharedKey, Endpoint: c.Endpoint, AllowedIPs: c.AllowedIPs, Keepalive: uint16(keepalive)}}
		config.AWG = awg.Config{}
	}

	if config.DNS != nil && config.DNS.NeedsNetwork() {
		if _, err := config.DNS.Normalize(config.Rules); err != nil {
			return config, err
		}
		if _, err := config.Rules.Normalize(); err != nil {
			return config, err
		}
		transport, err := config.Transport()
		if err != nil {
			return config, err
		}
		if _, err = transport.Capabilities(); err != nil {
			return config, err
		}
		return config, nil
	}
	if _, err := config.Compile(); err != nil {
		return config, err
	}
	return config, nil
}
