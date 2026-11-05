package dnspolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/StannisMod/amnezia-client/native/routing/rules"
)

// NetworkSnapshot is collected by the platform before replacing system DNS.
// SearchDomains are deliberately separate from actual per-domain routing rules.
type NetworkSnapshot struct {
	Links                   []NetworkLink `json:"links"`
	RoutingDomainsAvailable bool          `json:"routing_domains_available"`
}
type NetworkLink struct {
	ID            string          `json:"id"`
	Interface     string          `json:"interface"`
	Name          string          `json:"name,omitempty"`
	Default       bool            `json:"default"`
	Servers       []NetworkServer `json:"servers"`
	Domains       []string        `json:"domains,omitempty"`
	SearchDomains []string        `json:"search_domains,omitempty"`
	RoutingRules  []NetworkDomain `json:"routing_rules,omitempty"`
}
type NetworkDomain struct {
	Kind  rules.Kind `json:"kind"`
	Value string     `json:"value"`
}
type NetworkServer struct {
	Address    netip.Addr `json:"address"`
	Port       uint16     `json:"port,omitempty"`
	Transport  string     `json:"transport,omitempty"`
	ServerName string     `json:"server_name,omitempty"`
	HTTPSPath  string     `json:"https_path,omitempty"`
	// Android's opportunistic Private DNS encrypts without authenticating the
	// DNS server. This flag is native snapshot data, never a user policy option.
	OpportunisticTLS bool `json:"opportunistic_tls,omitempty"`
}

func (s NetworkSnapshot) Prepare(c Config) (Config, error) {
	if c.PreserveNetworkDomains && !s.RoutingDomainsAvailable {
		return Config{}, errors.New("this platform does not expose corporate DNS routing domains; configure explicit exceptions")
	}
	if len(s.Links) == 0 || len(s.Links) > 64 {
		return Config{}, errors.New("network DNS inventory is empty or exceeds its limit")
	}
	result := c
	result.Policies = make(map[string]Resolver, len(c.Policies))
	for id, p := range c.Policies {
		result.Policies[id] = p
	}
	seen := map[string]bool{}
	for _, link := range s.Links {
		if !validID(link.ID) || seen[link.ID] || len(link.Servers) == 0 || len(link.Servers) > 64 {
			return Config{}, errors.New("invalid network DNS link")
		}
		seen[link.ID] = true
		for _, server := range link.Servers {
			if server.Address.IsLoopback() {
				return Config{}, errors.New("network DNS cannot use a local stub")
			}
			if err := CheckAddress(server.Address, rules.Direct); err != nil {
				return Config{}, err
			}
			if server.OpportunisticTLS && server.Transport != "tls" {
				return Config{}, errors.New("invalid network DNS encryption mode")
			}
		}
	}
	apply := func(p Resolver, link NetworkLink) Resolver {
		server := link.Servers[0]
		p.Source = ""
		p.Server = server.Address.String()
		p.Interface = link.Interface
		if server.Port != 0 {
			p.Port = server.Port
		}
		if server.Transport != "" {
			p.Transport = server.Transport
			p.Port = server.Port
			p.ServerName = server.ServerName
			p.HTTPSPath = server.HTTPSPath
		}
		p.networkTLSOpportunistic = server.OpportunisticTLS
		return p
	}
	for id, p := range result.Policies {
		if p.Source != "network" {
			continue
		}
		var candidates []NetworkLink
		for _, link := range s.Links {
			if p.Interface != "" && (p.Interface == link.Interface || p.Interface == link.ID || p.Interface == link.Name) || p.Interface == "" && link.Default {
				candidates = append(candidates, link)
			}
		}
		if len(candidates) != 1 {
			return Config{}, errors.New("network DNS is missing or ambiguous; select a network interface")
		}
		result.Policies[id] = apply(p, candidates[0])
	}
	if c.PreserveNetworkDomains {
		result.NetworkRules = nil
		domains := map[string]string{}
		for _, link := range s.Links {
			if len(link.Domains) == 0 && len(link.RoutingRules) == 0 {
				continue
			}
			id := "network-" + link.ID
			if len(id) > 64 {
				return Config{}, errors.New("network DNS policy identifier exceeds limit")
			}
			if _, exists := result.Policies[id]; exists {
				return Config{}, errors.New("DNS policy identifier is reserved by the network")
			}
			result.Policies[id] = apply(Resolver{Name: "Network DNS", Transport: "udp", Path: rules.Direct}, link)
			matches := append([]NetworkDomain(nil), link.RoutingRules...)
			for _, domain := range link.Domains {
				matches = append(matches, NetworkDomain{Kind: rules.Suffix, Value: domain})
			}
			for _, match := range matches {
				if match.Kind != rules.Domain && match.Kind != rules.Suffix {
					return Config{}, errors.New("unsupported native DNS domain match")
				}
				name, err := rules.NormalizeDomain(strings.TrimPrefix(match.Value, "."))
				if err != nil {
					return Config{}, errors.New("invalid native DNS routing domain")
				}
				key := string(match.Kind) + ":" + name
				if previous, exists := domains[key]; exists && previous != id {
					return Config{}, errors.New("native DNS routing domain belongs to multiple networks")
				}
				if domains[key] == id {
					continue
				}
				domains[key] = id
				result.NetworkRules = append(result.NetworkRules, Rule{Kind: match.Kind, Value: name, Policy: id})
			}
		}
	}
	result.PreserveNetworkDomains = false
	return result, nil
}

func NetworkID(index uint64) string { return fmt.Sprintf("%d", index) }
