// SPDX-License-Identifier: Apache-2.0
package main

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/types"
)

type endpointDirections struct{ ingress, egress bool }

// affectedDirections conservatively indexes every matching compiled subject,
// including deny, pass, and default-deny-disabled rules. Only absence of rules
// proves a direction unrestricted. We deliberately over-include node/namespace
// scopes rather than risk skipping an applicable rule. The repository and its
// identity caches are immutable throughout this evaluation.
func affectedDirections(repo *policy.Repository, identities []*identity.Identity) []endpointDirections {
	out := make([]endpointDirections, len(identities))
	for i, id := range identities {
		if id.LabelArray.Has(labels.IDNameInit) {
			out[i] = endpointDirections{true, true}
		}
	}
	repo.Iterate(func(rule *types.PolicyEntry) {
		for i, id := range identities {
			if rule.Subject == nil || rule.Subject.Matches(id.LabelArray) {
				if rule.Ingress {
					out[i].ingress = true
				} else {
					out[i].egress = true
				}
			}
		}
	})
	return out
}
