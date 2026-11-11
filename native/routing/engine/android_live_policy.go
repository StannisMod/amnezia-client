package engine

import (
	"encoding/json"
	"errors"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
)

const liveAndroidPolicyKey = "amnezia_android_live_policy"

type liveAndroidPolicyOptions struct {
	Applications AndroidApplications `json:"applications"`
	Rules        []int               `json:"rules"`
}

type androidUIDSnapshot struct{ site map[int32]struct{} }
type liveAndroidPolicy struct {
	current atomic.Pointer[androidUIDSnapshot]
}

func newAndroidUIDSnapshot(apps AndroidApplications) (*androidUIDSnapshot, error) {
	if !apps.Live {
		return nil, errors.New("application policy is not live")
	}
	if _, err := apps.compile(); err != nil {
		return nil, err
	}
	snapshot := &androidUIDSnapshot{site: make(map[int32]struct{}, len(apps.SiteRulesUIDs))}
	for _, uid := range apps.SiteRulesUIDs {
		snapshot.site[int32(uid)] = struct{}{}
	}
	return snapshot, nil
}

// The delegates and their VPN actions never change after startup. Only the
// application condition changes; already routed TCP/UDP keep their outbound.
type liveAndroidRule struct {
	adapter.Rule
	policy *liveAndroidPolicy
}

func (r *liveAndroidRule) Match(metadata *adapter.InboundContext) bool {
	if !r.Rule.Match(metadata) {
		return false
	}
	if metadata.ProcessInfo == nil {
		return true
	}
	_, site := r.policy.current.Load().site[metadata.ProcessInfo.UserId]
	return !site
}

func splitLiveAndroidPolicy(raw []byte) ([]byte, *liveAndroidPolicyOptions, error) {
	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, nil, err
	}
	encoded, exists := config[liveAndroidPolicyKey]
	if !exists {
		return raw, nil, nil
	}
	var options liveAndroidPolicyOptions
	if err := json.Unmarshal(encoded, &options); err != nil {
		return nil, nil, err
	}
	if _, err := newAndroidUIDSnapshot(options.Applications); err != nil {
		return nil, nil, err
	}
	if len(options.Rules) == 0 {
		return nil, nil, errors.New("missing live application rules")
	}
	delete(config, liveAndroidPolicyKey)
	stripped, err := json.Marshal(config)
	return stripped, &options, err
}

func installLiveAndroidRules(rules []adapter.Rule, options *liveAndroidPolicyOptions) error {
	snapshot, err := newAndroidUIDSnapshot(options.Applications)
	if err != nil {
		return err
	}
	policy := new(liveAndroidPolicy)
	policy.current.Store(snapshot)
	seen := make(map[int]bool)
	for _, index := range options.Rules {
		if index < 0 || index >= len(rules) || seen[index] {
			return errors.New("invalid live application rule index")
		}
		action, ok := rules[index].Action().(*R.RuleActionRoute)
		if !ok || action.Outbound != "vpn" {
			return errors.New("live condition requires VPN override")
		}
		seen[index] = true
	}
	// Called before Box.Start: the routing goroutines never see slice writes.
	for _, index := range options.Rules {
		rules[index] = &liveAndroidRule{Rule: rules[index], policy: policy}
	}
	return nil
}

// Only UID membership and the real DNS generation may vary in this operation.
// Capture, transport, destination rules and their order must remain identical.
func liveAndroidInvariant(raw []byte) (string, *liveAndroidPolicyOptions, error) {
	_, options, err := splitLiveAndroidPolicy(raw)
	if err != nil || options == nil {
		return "", nil, errors.New("missing live application policy")
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw, &config); err != nil {
		return "", nil, err
	}
	stable := *options
	stable.Applications.SiteRulesUIDs = nil
	encoded, err := json.Marshal(stable)
	if err != nil {
		return "", nil, err
	}
	config[liveAndroidPolicyKey] = encoded
	delete(config, "dns")
	encoded, err = json.Marshal(config)
	return string(encoded), options, err
}

func findLiveAndroidPolicy(rules []adapter.Rule) *liveAndroidPolicy {
	for _, rule := range rules {
		if live, ok := rule.(*liveAndroidRule); ok {
			return live.policy
		}
	}
	return nil
}
