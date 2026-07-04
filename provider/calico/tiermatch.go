// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Telepathy Authors
//
// This file is part of Telepathy.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calico

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
// AND host endpoint, the tiers and policies that select it.
func ResolveTierMatches(req Request) TierMatchResponse {
	g := buildGraph(req, nil)
	resp := TierMatchResponse{Warnings: g.warnings, Errors: g.errors}

	for _, id := range sortedKeys(g.wepByID) {
		tm := TierMatch{Endpoint: id}
		collectTiers(&tm, g.wepByID[id].GetTiers())
		resp.Endpoints = append(resp.Endpoints, tm)
	}

	// HostEndpoints are policy subjects too: a GlobalNetworkPolicy selecting a
	// HEP is exactly what the host-firewall lessons rely on. Unlike a workload, a
	// HEP carries four tier lists - the normal tiers plus the applyOnForward /
	// preDNAT / doNotTrack overlays (see eval.go's *WEP accessors) - so a
	// host-firewall policy lands in one of the latter three, not GetTiers(). Walk
	// all four, or the tier view stays blank for the very policies HEPs exist to
	// carry. Keyed "host/<name>" to match the matrix/actor id (eval.go:521).
	for _, name := range sortedKeys(g.hepByName) {
		hep := g.hepByName[name]
		tm := TierMatch{Endpoint: "host/" + name}
		collectTiers(&tm, hep.GetTiers(), hep.GetForwardTiers(), hep.GetPreDnatTiers(), hep.GetUntrackedTiers())
		resp.Endpoints = append(resp.Endpoints, tm)
	}
	return resp
}

// collectTiers records, into tm, the tiers that select this endpoint (some
// policy in the tier does) and the deduped ingress∪egress policies from the
// given tier lists. Accepts several lists because a HEP has four (normal +
// forward/preDNAT/untracked overlays); tiers and policies are deduped across
// them so a tier or policy appearing in more than one list is reported once.
func collectTiers(tm *TierMatch, tierLists ...[]*proto.TierInfo) {
	seenPol := map[types.PolicyID]bool{}
	seenTier := map[string]bool{}
	for _, tiers := range tierLists {
		for _, ti := range tiers {
			pols := append(append([]*proto.PolicyID{}, ti.GetIngressPolicies()...), ti.GetEgressPolicies()...)
			if len(pols) == 0 {
				continue // tier in the chain but no policy here selects this endpoint
			}
			if !seenTier[ti.GetName()] {
				seenTier[ti.GetName()] = true
				tm.Tiers = append(tm.Tiers, ti.GetName())
			}
			for _, p := range pols {
				pid := types.ProtoToPolicyID(p)
				if seenPol[pid] {
					continue
				}
				seenPol[pid] = true
				tm.Policies = append(tm.Policies, PolicyRef{Kind: pid.Kind, Namespace: pid.Namespace, Name: pid.Name})
			}
		}
	}
}
