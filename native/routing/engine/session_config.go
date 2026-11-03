package engine

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/StannisMod/amnezia-client/native/routing/tunnel"
	"github.com/StannisMod/amnezia-client/native/routing/wireguard"
)

// TransportConfig accepts supported adapters, never raw sing-box outbounds.
type TransportConfig struct {
	Type      string            `json:"type"`
	AWG       *awg.Config       `json:"awg,omitempty"`
	WireGuard *wireguard.Config `json:"wireguard,omitempty"`
}

func (c TransportConfig) Capabilities() (tunnel.Capabilities, error) {
	switch {
	case c.Type == "awg" && c.AWG != nil && c.WireGuard == nil:
		if err := c.AWG.Validate(); err != nil {
			return tunnel.Capabilities{}, err
		}
	case c.Type == "wireguard" && c.WireGuard != nil && c.AWG == nil:
		if err := c.WireGuard.Validate(); err != nil {
			return tunnel.Capabilities{}, err
		}
	default:
		return tunnel.Capabilities{}, errors.New("unsupported or ambiguous VPN transport")
	}
	return tunnel.Capabilities{TCP: true, UDP: true}, nil
}
func (c TransportConfig) outbound() (map[string]any, error) {
	if _, err := c.Capabilities(); err != nil {
		return nil, err
	}
	var value any = c.AWG
	kind := awg.Type
	if c.Type == "wireguard" {
		value = c.WireGuard
		kind = wireguard.Type
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("invalid VPN transport")
	}
	var vpn map[string]any
	if err = json.Unmarshal(raw, &vpn); err != nil {
		return nil, err
	}
	vpn["type"] = kind
	vpn["tag"] = "vpn"
	return vpn, nil
}

// SessionConfig keeps legacy AWG JSON readable. Platform hosts own capture,
// socket protection and OS restoration; new hosts supply an explicit transport.
type SessionConfig struct {
	NetworkDNS            *dnspolicy.NetworkSnapshot `json:"network_dns,omitempty"`
	DNSNetworkFingerprint string                     `json:"dns_network_fingerprint,omitempty"`
	Rules                 rules.Config               `json:"rules"`
	AWG                   awg.Config                 `json:"awg,omitempty"`
	VPN                   *TransportConfig           `json:"vpn,omitempty"`
	Resolver              netip.AddrPort             `json:"resolver"`
	ResolverAction        rules.Action               `json:"resolver_action"`
	Applications          *ApplicationScope          `json:"applications,omitempty"`
	DNS                   *dnspolicy.Config          `json:"dns,omitempty"`
}

func (c SessionConfig) Transport() (TransportConfig, error) {
	if c.VPN != nil {
		if !reflect.DeepEqual(c.AWG, awg.Config{}) {
			return TransportConfig{}, errors.New("ambiguous legacy and explicit VPN transport")
		}
		return *c.VPN, nil
	}
	return TransportConfig{Type: "awg", AWG: &c.AWG}, nil
}
func (c SessionConfig) PeerPublicKey() string {
	transport, err := c.Transport()
	if err != nil {
		return ""
	}
	if transport.Type == "wireguard" && transport.WireGuard != nil {
		return transport.WireGuard.PublicKey
	}
	if transport.AWG != nil {
		return transport.AWG.PublicKey
	}
	return ""
}
func (c SessionConfig) Compile() ([]byte, error) {
	transport, err := c.Transport()
	if err != nil {
		return nil, err
	}
	vpn, err := transport.outbound()
	if err != nil {
		return nil, err
	}
	return (RoutingConfig{Rules: c.Rules, Resolver: c.Resolver, ResolverAction: c.ResolverAction, Applications: c.Applications, DNS: c.DNS}).compile(vpn)
}
