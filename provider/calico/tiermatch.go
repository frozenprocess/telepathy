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
// EndOfTierFlows maps a tier name to how many directional flows (src→dst pairs,
// for the Request's probe) reach that tier's end-of-tier default action — a
// "partial match": the tier's policies select an endpoint on the path but no
// rule in the tier decides the flow, so it falls through to the tier's default.
type TierMatchResponse struct {
	Endpoints      []TierMatch    `json:"endpoints"`
	EndOfTierFlows map[string]int `json:"endOfTierFlows,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"`
	Errors         []string       `json:"errors,omitempty"`
}

// ResolveTierMatches builds the calc graph for req and reports, per workload
// AND host endpoint, the tiers and policies that select it.
//
// This is a VISIBILITY view, so staged policies are always included: a
// Staged{,Global,Kubernetes}NetworkPolicy selects endpoints and shows what would
// happen to a flow, it just doesn't enforce. Evaluate (the connectivity matrix)
// still honours req.EvaluateStaged, so enforcement is unchanged — only this
// selection/preview report forces staged in.
func ResolveTierMatches(req Request) TierMatchResponse {
	req.EvaluateStaged = true
	g := buildGraph(req, nil)
	resp := TierMatchResponse{Warnings: g.warnings, Errors: g.errors}

	// Workload endpoints: the tiers/policies that select each WEP, in the calc
	// graph's tier order.
	for _, id := range sortedKeys(g.wepByID) {
		wep := g.wepByID[id]
		tm := TierMatch{Endpoint: id}
		seen := map[types.PolicyID]bool{}
		seenTier := map[string]bool{}
		collectTierPolicies(&tm, seen, seenTier, wep.GetTiers())
		resp.Endpoints = append(resp.Endpoints, tm)
	}

	// Host endpoints. A HEP is a GlobalNetworkPolicy subject, NOT a tier of its
	// own — its policies live in ordinary tiers (reserved or custom, any order).
	// The calc graph splits a HEP's rules into four lists by enforcement point:
	// PreDnat (preDNAT), Untracked (doNotTrack) and Forward (applyOnForward)
	// hooks all fire ahead of the normal tier chain — a preDNAT policy sitting in
	// a low-precedence tier is still evaluated before a normal-tier policy —
	// while the normal Tiers walk in tier order. Each policy nevertheless BELONGS
	// to whatever tier it declares, so we report the real TierInfo.Name from
	// every list, deduped across all four. buildActors applies the same
	// doNotTrack-on-"*" suppression the matrix uses, so the reported footprint
	// matches what the dataplane actually enforces; its warnings are merged.
	bundle := buildActors(req, g.wepByID, g.hepByName)
	resp.Warnings = append(resp.Warnings, bundle.warnings...)
	for _, a := range bundle.list {
		if a.kind != actorHEP {
			continue
		}
		tm := TierMatch{Endpoint: a.id}
		seen := map[types.PolicyID]bool{}
		seenTier := map[string]bool{}
		// Evaluation order: the pre-normal hooks first, then the normal tiers.
		collectTierPolicies(&tm, seen, seenTier, a.hep.GetPreDnatTiers())
		collectTierPolicies(&tm, seen, seenTier, a.hep.GetUntrackedTiers())
		collectTierPolicies(&tm, seen, seenTier, a.hep.GetForwardTiers())
		collectTierPolicies(&tm, seen, seenTier, a.hep.GetTiers())
		resp.Endpoints = append(resp.Endpoints, tm)
	}

	// End-of-tier flow accounting: run the SAME per-flow policy walk the matrix
	// uses (evalFlow) over every ordered actor pair and count, per tier, how many
	// flows reach that tier's end-of-tier default action. Deduped per flow by
	// evalFlow (its eot set), so a flow that hits a tier's end-of-tier action on
	// both its egress and ingress leg still counts once for that tier.
	mkFlow := flowFactory(req)
	eotFlows := map[string]int{}
	for _, src := range bundle.list {
		for _, dst := range bundle.list {
			if src.id == dst.id {
				continue
			}
			if _, eot := evalFlow(g.store, src, dst, mkFlow(src, dst), mkFlow(dst, src), bundle.hepsByNode); len(eot) > 0 {
				for t := range eot {
					eotFlows[t]++
				}
			}
		}
	}
	if len(eotFlows) > 0 {
		resp.EndOfTierFlows = eotFlows
	}
	return resp
}

// collectTierPolicies appends, for each tier in tiers that carries a policy
// selecting the endpoint, the tier name (once) and its ingress ∪ egress
// policies, deduped by PolicyID across the whole endpoint. seen/seenTier are
// shared across calls so a HEP's four tier lists dedupe against each other (the
// same tier can hold both a preDNAT and a normal policy).
func collectTierPolicies(tm *TierMatch, seen map[types.PolicyID]bool, seenTier map[string]bool, tiers []*proto.TierInfo) {
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
			if seen[pid] {
				continue
			}
			seen[pid] = true
			tm.Policies = append(tm.Policies, PolicyRef{Kind: pid.Kind, Namespace: pid.Namespace, Name: pid.Name})
		}
	}
}
