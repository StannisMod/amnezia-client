package engine

import (
	"context"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	J "github.com/sagernet/sing/common/json"
)

// Packet pre-matching runs synchronously on sing-tun's packet reader. A
// resolve action here can wait for a dead VPN DNS server and stop unrelated
// packets, including the SYN of a DIRECT connection. TCP/UDP already have
// asynchronous connection handlers which evaluate the complete policy.
// The pinned router returns PreMatchContinue for an unhandled action. This
// private sentinel is only matched during pre-matching; normal routing always
// evaluates the original policy. Its behavior is covered against the actual
// router so dependency upgrades cannot silently turn it into a policy bypass.
type packetPreMatchGuard struct{ adapter.Rule }

type deferPacketAction struct{}

func (deferPacketAction) Type() string                    { return "amnezia-defer-packet-policy" }
func (deferPacketAction) String() string                  { return "defer packet policy to connection handler" }
func (r *packetPreMatchGuard) Action() adapter.RuleAction { return deferPacketAction{} }
func (r *packetPreMatchGuard) Match(m *adapter.InboundContext) bool {
	return m.PreMatch && m.Inbound == TUNTag && (m.Network == "tcp" || m.Network == "udp")
}

func preparePacketPreMatchGuard(ctx context.Context, options *option.Options) (bool, error) {
	if options.Route == nil {
		return false, nil
	}
	var guard option.Rule
	if err := J.UnmarshalContext(ctx, []byte(`{"action":"sniff","sniffer":["tls"]}`), &guard); err != nil {
		return false, err
	}
	options.Route.Rules = append([]option.Rule{guard}, options.Route.Rules...)
	return true, nil
}
