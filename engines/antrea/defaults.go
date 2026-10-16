// SPDX-License-Identifier: Apache-2.0
package main

import "github.com/frozenprocess/telepathy/api"

// An empty rule list can still isolate an endpoint. Keep that state separate
// from the rules so an explicit default-deny policy never becomes allow-all.
type directionRules struct {
	isolated bool
	rules    []resolvedRule
}

type endpointPolicies struct{ ingress, egress directionRules }

func indexEndpointPolicies(m model, endpoints []api.Endpoint, protocol string, port int) []endpointPolicies {
	byPod := make(map[string]endpointPolicies)
	for _, policy := range m.policies {
		for key, selected := range policy.appliedTo {
			if !selected {
				continue
			}
			ep := byPod[key]
			if policy.ingressIsolate {
				ep.ingress.isolated = true
				ep.ingress.rules = append(ep.ingress.rules, policy.ingress...)
			}
			if policy.egressIsolate {
				ep.egress.isolated = true
				ep.egress.rules = append(ep.egress.rules, policy.egress...)
			}
			byPod[key] = ep
		}
	}
	out := make([]endpointPolicies, len(endpoints))
	for i, ep := range endpoints {
		policies := byPod[podKey(ep)]
		out[i] = endpointPolicies{ingress: policies.ingress.forProbe(protocol, port, &ep), egress: policies.egress.forProbe(protocol, port, nil)}
	}
	return out
}

func (d directionRules) allows(peer api.Endpoint, protocol string, port int, owner api.Endpoint) bool {
	if !d.isolated {
		return true
	}
	for _, rule := range d.rules {
		if rule.matches(peer, protocol, port, owner) {
			return true
		}
	}
	return false
}

// Eliminate rules whose protocol/port cannot match this probe. Ingress named
// ports belong to the fixed owner; egress named ports depend on the destination
// and must stay dynamic. Isolation survives even when every rule is eliminated.
func (d directionRules) forProbe(protocol string, port int, owner *api.Endpoint) directionRules {
	filtered := directionRules{isolated: d.isolated}
	for _, rule := range d.rules {
		dynamic := false
		if owner == nil {
			for _, p := range rule.ports {
				if p.named != "" {
					dynamic = true
					break
				}
			}
		}
		if !dynamic {
			endpoint := api.Endpoint{}
			if owner != nil {
				endpoint = *owner
			}
			if !rule.portMatches(protocol, port, endpoint) {
				continue
			}
			if rule.matchAllPeers {
				return directionRules{}
			} // additive allow-all
			rule.ports = nil // already matched for this probe
		}
		filtered.rules = append(filtered.rules, rule)
	}
	return filtered
}
