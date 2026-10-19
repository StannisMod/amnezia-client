package desktop

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
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

// ProfileSession converts the same native AWG profile used by the Qt client.
// No resolved legacy site addresses or raw backend configuration is accepted.
// Desktop per-app and OS kill-switch integration are still gated explicitly.
func ProfileSession(raw []byte) (engine.SessionConfig, error) {
	var profile struct {
		Protocol   string         `json:"protocol"`
		DNS        string         `json:"dns1"`
		DNSPath    rules.Action   `json:"sing_box_dns_path"`
		Rules      rules.Config   `json:"sing_box_routing"`
		AWG        map[string]any `json:"awg_config_data"`
		AppScope   int            `json:"appSplitTunnelType"`
		KillSwitch any            `json:"killSwitchOption"`
	}
	if len(raw) > 4<<20 {
		return engine.SessionConfig{}, errors.New("routing profile exceeds size limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&profile); err != nil || profile.Protocol != "awg" {
		return engine.SessionConfig{}, errors.New("routed desktop sessions require an AWG profile")
	}
	if profile.AppScope != 0 {
		return engine.SessionConfig{}, errors.New("desktop domain routing with application exclusions is not yet supported")
	}
	if text(profile.KillSwitch) == "true" || text(profile.KillSwitch) == "1" {
		return engine.SessionConfig{}, errors.New("desktop domain routing with the OS kill switch is not yet supported")
	}
	resolver, err := netip.ParseAddr(profile.DNS)
	if err != nil {
		return engine.SessionConfig{}, errors.New("a numeric DNS resolver is required")
	}
	config := engine.SessionConfig{Rules: profile.Rules, Resolver: netip.AddrPortFrom(resolver, 53), ResolverAction: profile.DNSPath}
	if config.ResolverAction == "" {
		config.ResolverAction = rules.VPN
	}
	if resolver.IsLoopback() {
		config.ResolverAction = rules.Direct
	}
	wg := profile.AWG
	endpoint, err := netip.ParseAddr(text(wg["hostName"]))
	if err != nil {
		return config, errors.New("AWG endpoint must be bootstrapped before OS capture")
	}
	port, err := strconv.ParseUint(text(wg["port"]), 10, 16)
	if err != nil || port == 0 {
		return config, errors.New("invalid AWG endpoint port")
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
				return config, errors.New("invalid AWG interface address")
			}
		}
		config.AWG.Address = append(config.AWG.Address, a)
	}
	allowed, ok := wg["allowed_ips"].([]any)
	if !ok {
		return config, errors.New("AWG allowed IPs must be a list")
	}
	default4 := false
	for _, value := range allowed {
		p, err := netip.ParsePrefix(text(value))
		if err != nil {
			return config, errors.New("invalid AWG allowed IP prefix")
		}
		config.AWG.AllowedIPs = append(config.AWG.AllowedIPs, p)
		default4 = default4 || p == netip.MustParsePrefix("0.0.0.0/0")
	}
	if !default4 {
		return config, errors.New("domain routing requires the AWG IPv4 default route")
	}
	if value := text(wg["mtu"]); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return config, errors.New("invalid AWG MTU")
		}
		config.AWG.MTU = n
	}
	if value := text(wg["persistent_keep_alive"]); value != "" {
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return config, errors.New("invalid AWG keepalive")
		}
		config.AWG.Keepalive = uint16(n)
	}
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
	if _, err := config.Compile(); err != nil {
		return config, err
	}
	return config, nil
}
