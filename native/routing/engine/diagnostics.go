package engine

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

// Diagnostics reports routing choices rather than transport success. Counters
// and the last reason stay in memory; no destination names or addresses are kept.
type DiagnosticSnapshot struct {
	UnknownOwner     uint64 `json:"unknown_owner"`
	LastOwnerKnown   bool   `json:"last_owner_known"`
	Direct           uint64 `json:"direct"`
	VPN              uint64 `json:"vpn"`
	ManagedDNS       uint64 `json:"managed_dns"`
	Sniffed          uint64 `json:"sniffed"`
	NoDomain         uint64 `json:"no_domain"`
	Default          uint64 `json:"default"`
	LastOutbound     string `json:"last_outbound,omitempty"`
	LastReason       string `json:"last_reason,omitempty"`
	LastRule         string `json:"last_rule,omitempty"`
	LastNetwork      string `json:"last_network,omitempty"`
	LastDomainSource string `json:"last_domain_source,omitempty"`
}
type Diagnostics struct {
	mu       sync.Mutex
	snapshot DiagnosticSnapshot
}

func (d *Diagnostics) Snapshot() DiagnosticSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.snapshot
}
func (d *Diagnostics) record(m adapter.InboundContext, rule adapter.Rule, out adapter.Outbound) {
	if m.Inbound != TUNTag || out == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	s := &d.snapshot
	s.LastOwnerKnown = m.ProcessInfo != nil && m.ProcessInfo.UserId >= 0
	if !s.LastOwnerKnown {
		s.UnknownOwner++
	}
	s.LastOutbound = out.Tag()
	s.LastNetwork = m.Network
	s.LastRule = ""
	switch out.Tag() {
	case "direct":
		s.Direct++
	case "vpn":
		s.VPN++
	}
	switch {
	case m.FakeIP || m.Destination.IsDomain():
		s.ManagedDNS++
		s.LastDomainSource = "managed_dns"
	case m.Domain != "":
		s.Sniffed++
		s.LastDomainSource = "sniff"
	default:
		s.NoDomain++
		s.LastDomainSource = "unavailable"
	}
	if rule == nil {
		s.Default++
		s.LastReason = "default"
	} else {
		s.LastReason = "rule"
		s.LastRule = rule.String()
		if len(s.LastRule) > 512 {
			s.LastRule = s.LastRule[:512]
		}
	}
}
func (d *Diagnostics) RoutedConnection(_ context.Context, c net.Conn, m adapter.InboundContext, r adapter.Rule, o adapter.Outbound) net.Conn {
	d.record(m, r, o)
	return c
}
func (d *Diagnostics) RoutedPacketConnection(_ context.Context, c N.PacketConn, m adapter.InboundContext, r adapter.Rule, o adapter.Outbound) N.PacketConn {
	d.record(m, r, o)
	return c
}
func (d *Diagnostics) RoutedFlow(_ context.Context, m adapter.InboundContext, r adapter.Rule, o adapter.Outbound) tun.FlowTracker {
	d.record(m, r, o)
	return nil
}
