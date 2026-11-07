// Package tunnel defines the contract shared by VPN transport adapters.
package tunnel

import "net/netip"

type Stats struct{ RXBytes, TXBytes, LastHandshake uint64 }
type Capabilities struct {
	TCP bool `json:"tcp"`
	UDP bool `json:"udp"`
}
type Statistics interface{ Stats() (Stats, error) }

// UnderlayRefresher preserves established inner flows. Zero retains the current
// endpoint; a supplied numeric endpoint may change only the same peer's address.
type UnderlayRefresher interface{ RefreshUnderlay(netip.AddrPort) error }
