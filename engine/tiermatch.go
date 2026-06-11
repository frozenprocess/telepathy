// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 The Telepathy Authors
//
// This file is part of Telepathy.
//
// Telepathy is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License version 3 as published
// by the Free Software Foundation.
//
// Telepathy is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.

package engine

// tiermatch.go answers "which policies/tiers actually select each endpoint",
// using the same resolved calc graph the matrix/BPF/iptables paths use. The
// editor's tier view consumes this to highlight, for a selected endpoint, the
// policy cards that select it and the tiers whose end-of-tier default action is
// in its evaluation path.
//
// This is the authoritative answer (Calico's own label index resolves it —
// namespace scoping, inherited namespace/service-account labels, GNP cluster
// scope, CNP subjects), not a client-side selector approximation.

import (
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

// PolicyRef identifies a resolved policy the way the calc graph names it. Name
// is the verbatim metadata.name; Kind is normalised by the model
// ("NetworkPolicy", "GlobalNetworkPolicy", "KubernetesNetworkPolicy",
// "KubernetesClusterNetworkPolicy"); Namespace is "" for cluster-scoped kinds.
type PolicyRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// TierMatch is one endpoint's resolved policy footprint: the tiers it's subject
// to (i.e. some policy in the tier selects it, so the tier's end-of-tier action
// is in its path) and the policies (ingress ∪ egress, deduped) that select it.
type TierMatch struct {
	Endpoint string      `json:"endpoint"`
	Tiers    []string    `json:"tiers"`
	Policies []PolicyRef `json:"policies"`
}

// TierMatchResponse is the per-endpoint matches plus feed-time warnings/errors.
type TierMatchResponse struct {
	Endpoints []TierMatch `json:"endpoints"`
	Warnings  []string    `json:"warnings,omitempty"`
	Errors    []string    `json:"errors,omitempty"`
}

// ResolveTierMatches builds the calc graph for req and reports, per workload
// endpoint, the tiers and policies that select it.
func ResolveTierMatches(req Request) TierMatchResponse {
	g := buildGraph(req, nil)
	resp := TierMatchResponse{Warnings: g.warnings, Errors: g.errors}

	for _, id := range sortedKeys(g.wepByID) {
		wep := g.wepByID[id]
		tm := TierMatch{Endpoint: id}
		seen := map[types.PolicyID]bool{}
		for _, ti := range wep.GetTiers() {
			pols := append(append([]*proto.PolicyID{}, ti.GetIngressPolicies()...), ti.GetEgressPolicies()...)
			if len(pols) == 0 {
				continue // tier in the chain but no policy here selects this endpoint
			}
			tm.Tiers = append(tm.Tiers, ti.GetName())
			for _, p := range pols {
				pid := types.ProtoToPolicyID(p)
				if seen[pid] {
					continue
				}
				seen[pid] = true
				tm.Policies = append(tm.Policies, PolicyRef{Kind: pid.Kind, Namespace: pid.Namespace, Name: pid.Name})
			}
		}
		resp.Endpoints = append(resp.Endpoints, tm)
	}
	return resp
}
