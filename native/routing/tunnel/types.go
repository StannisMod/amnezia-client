// Package tunnel defines the contract shared by VPN transport adapters.
package tunnel

type Stats struct{ RXBytes, TXBytes, LastHandshake uint64 }
type Capabilities struct {
	TCP bool `json:"tcp"`
	UDP bool `json:"udp"`
}
type Statistics interface{ Stats() (Stats, error) }
