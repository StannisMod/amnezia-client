// Package awg adapts the pinned AWG 3.1 device to a flow-based dialer. Its
// in-memory TUN is private to AWG, never the application's OS VPN descriptor.
package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

type Config struct {
	Address      []netip.Addr `json:"address"`
	DNS          []netip.Addr `json:"dns,omitempty"`
	MTU          int          `json:"mtu,omitempty"`
	PrivateKey   string       `json:"private_key"`
	PublicKey    string       `json:"public_key"`
	PreSharedKey string       `json:"pre_shared_key,omitempty"`
	// Endpoint is resolved through the host's underlay bootstrap before start.
	Endpoint   netip.AddrPort    `json:"endpoint"`
	AllowedIPs []netip.Prefix    `json:"allowed_ips"`
	Keepalive  uint16            `json:"keepalive,omitempty"`
	ListenPort uint16            `json:"listen_port,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

var parameters = strings.Fields("jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 header_protection_key content_padding_addition rekey_after_time rekey_timeout reject_after_time keepalive_timeout max_handshake_attempts random_trailers disable_cookies")

func keyHex(s string) (string, error) {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != 32 {
		return "", errors.New("invalid 32-byte AWG key")
	}
	return hex.EncodeToString(b), nil
}

func (c Config) uapi() (string, error) {
	if len(c.Address) == 0 || !c.Endpoint.IsValid() || c.Endpoint.Port() == 0 || len(c.AllowedIPs) == 0 {
		return "", errors.New("AWG address, numeric endpoint and allowed IPs are required")
	}
	for _, a := range c.Address {
		if !a.IsValid() || a.IsUnspecified() {
			return "", errors.New("invalid AWG local address")
		}
	}
	sk, e := keyHex(c.PrivateKey)
	if e != nil {
		return "", e
	}
	pk, e := keyHex(c.PublicKey)
	if e != nil {
		return "", e
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\n", sk, c.ListenPort)
	keys := make([]string, 0, len(c.Parameters))
	for k := range c.Parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ok := false
		for _, allowed := range parameters {
			if k == allowed {
				ok = true
				break
			}
		}
		v := c.Parameters[k]
		if !ok || strings.ContainsAny(v, "\r\n\x00") {
			return "", errors.New("invalid AWG extension parameter")
		}
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	fmt.Fprintf(&b, "replace_peers=true\npublic_key=%s\n", pk)
	if c.PreSharedKey != "" {
		psk, e := keyHex(c.PreSharedKey)
		if e != nil {
			return "", e
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	fmt.Fprintf(&b, "endpoint=%s\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", c.Endpoint, c.Keepalive)
	for _, p := range c.AllowedIPs {
		if !p.IsValid() {
			return "", errors.New("invalid allowed IP")
		}
		fmt.Fprintf(&b, "allowed_ip=%s\n", p.Masked())
	}
	return b.String(), nil
}

type Transport struct {
	Net      *FlowStack
	device   *device.Device
	mu       sync.RWMutex
	closed   bool
	address4 netip.Addr
	address6 netip.Addr
}

type Stats struct{ RXBytes, TXBytes, LastHandshake uint64 }

// Stats returns only counters and a timestamp, never private UAPI material.
func (t *Transport) Stats() (Stats, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return Stats{}, net.ErrClosed
	}
	raw, err := t.device.IpcGet()
	if err != nil {
		return Stats{}, errors.New("AWG statistics unavailable")
	}
	var stats Stats
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(value, 10, 64)
		switch key {
		case "rx_bytes":
			stats.RXBytes += n
		case "tx_bytes":
			stats.TXBytes += n
		case "last_handshake_time_sec":
			if n > stats.LastHandshake {
				stats.LastHandshake = n
			}
		}
	}
	return stats, nil
}

func New(ctx context.Context, c Config, listen ListenUnderlay) (*Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Endpoint.IsValid() {
		c.Endpoint = netip.AddrPortFrom(c.Endpoint.Addr().Unmap(), c.Endpoint.Port())
	}
	if listen == nil {
		return nil, errors.New("protected underlay socket factory is required")
	}
	ipc, e := c.uapi()
	if e != nil {
		return nil, e
	}
	if c.MTU == 0 {
		c.MTU = 1280
	}
	if c.MTU < 1280 || c.MTU > 65535 {
		return nil, errors.New("AWG MTU outside supported range")
	}
	tun, n, e := NewFlowTUN(c.Address, c.MTU)
	if e != nil {
		return nil, errors.New("create AWG flow stack failed")
	}
	bind := &packetBind{ctx: ctx, listen: listen, endpoint: c.Endpoint}
	d, e := NewConfiguredDevice(tun, bind, ipc)
	if e != nil {
		return nil, errors.New("AWG configuration or underlay startup failed")
	}
	t := &Transport{Net: n, device: d}
	for _, a := range c.Address {
		if a.Is4() && !t.address4.IsValid() {
			t.address4 = a
		}
		if a.Is6() && !t.address6.IsValid() {
			t.address6 = a
		}
	}
	return t, nil
}

func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	t.device.Close()
	return nil
}
func (t *Transport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	t.mu.RLock()
	closed := t.closed
	t.mu.RUnlock()
	if closed {
		return nil, net.ErrClosed
	}
	return t.Net.DialContext(ctx, network, address)
}
func (t *Transport) ListenPacket(ctx context.Context, destination netip.Addr) (net.PacketConn, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	local := t.address4
	if destination.Is6() {
		local = t.address6
	}
	if !local.IsValid() {
		return nil, errors.New("AWG has no local address for the UDP destination family")
	}
	conn, err := t.Net.ListenUDPAddrPort(netip.AddrPortFrom(local, 0))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// LocalPort supports diagnostics/tests without exposing the private UAPI.
func (t *Transport) LocalPort() (uint16, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return 0, net.ErrClosed
	}
	s, e := t.device.IpcGet()
	if e != nil {
		return 0, errors.New("AWG status unavailable")
	}
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			n, e := strconv.ParseUint(v, 10, 16)
			return uint16(n), e
		}
	}
	return 0, errors.New("AWG listen port unavailable")
}
