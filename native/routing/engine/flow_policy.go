package engine

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	J "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// Platform policy may refuse new captured flows without destroying existing
// sockets, the capture interface, or the internal DNS/underlay recovery path.
type newFlowPolicy struct {
	paused    atomic.Bool
	installed bool
}

type newFlowPolicyRule struct {
	adapter.Rule
	policy *newFlowPolicy
}

func (r *newFlowPolicyRule) Match(m *adapter.InboundContext) bool {
	return !m.PreMatch && r.policy.paused.Load() && r.Rule.Match(m)
}

func prepareNewFlowPolicy(ctx context.Context, options *option.Options) (*newFlowPolicy, error) {
	policy := service.FromContext[*newFlowPolicy](ctx)
	if policy == nil || options.Route == nil {
		return nil, nil
	}
	var reject option.Rule
	if err := J.UnmarshalContext(ctx, []byte(`{"inbound":"amnezia-tun","action":"reject"}`), &reject); err != nil {
		return nil, err
	}
	options.Route.Rules = append([]option.Rule{reject}, options.Route.Rules...)
	return policy, nil
}

func (s *Runtime) SetNewFlowsPaused(paused bool) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed || s.flowPolicy == nil || !s.flowPolicy.installed {
		return errors.New("flow policy is unavailable")
	}
	s.flowPolicy.paused.Store(paused)
	return nil
}
