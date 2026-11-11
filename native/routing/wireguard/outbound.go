// Package wireguard uses the existing device in compatibility mode, with
// AWG extensions excluded by its public schema.
package wireguard

import (
	"context"
	"net/netip"
	"strconv"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
)

const Type = "amnezia-wireguard"

type Config struct {
	PathMTUProbe netip.Addr     `json:"path_mtu_probe,omitempty"`
	Address      []netip.Addr   `json:"address"`
	MTU          int            `json:"mtu,omitempty"`
	PrivateKey   string         `json:"private_key"`
	PublicKey    string         `json:"public_key"`
	PreSharedKey string         `json:"pre_shared_key,omitempty"`
	Endpoint     netip.AddrPort `json:"endpoint"`
	AllowedIPs   []netip.Prefix `json:"allowed_ips"`
	Keepalive    uint16         `json:"keepalive,omitempty"`
	ListenPort   uint16         `json:"listen_port,omitempty"`
}

func (c Config) Native() awg.Config {
	return awg.Config{Address: c.Address, MTU: c.MTU, PrivateKey: c.PrivateKey, PublicKey: c.PublicKey, PreSharedKey: c.PreSharedKey, Endpoint: c.Endpoint, AllowedIPs: c.AllowedIPs, Keepalive: awg.Keepalive(strconv.Itoa(int(c.Keepalive))), ListenPort: c.ListenPort, PathMTUProbe: c.PathMTUProbe}
}
func (c Config) Validate() error { return c.Native().Validate() }
func Register(r *outbound.Registry, listen awg.ListenUnderlay) {
	outbound.Register[Config](r, Type, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, c Config) (adapter.Outbound, error) {
		o, err := awg.NewOutbound(ctx, tag, c.Native(), listen)
		if err != nil {
			return nil, err
		}
		o.Adapter = outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil)
		return o, nil
	})
}
