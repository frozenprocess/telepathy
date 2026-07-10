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

import (
	"strings"

	"github.com/projectcalico/calico/felix/proto"

	"github.com/frozenprocess/telepathy/api"
)

// costDataplane is Calico's api.DataplaneWeight: the exact cost this policy set
// compiles to, not an estimate. req.CostDataplane selects the dataplane —
// "iptables" (default) counts programmed rules; "bpf" counts eBPF instructions.
//
// Either count is topology-dependent (more endpoints => more per-endpoint
// chains/programs), which is correct: it reflects the real cost of enforcing
// this policy set on this topology. Use it to compare revisions of a policy set
// on a fixed topology; it is not comparable across engines or across dataplanes
// (rules vs instructions are different units — see api.DataplaneWeight).
func costDataplane(req Request) *api.DataplaneWeight {
	var w *api.DataplaneWeight
	switch req.CostDataplane {
	case "bpf", "ebpf":
		w = bpfWeight(req)
	case "nftables", "nft":
		// nft rule bodies are indented inside `chain NAME { ... }`; the chain
		// open/close lines are not. The nft renderer is more compact than
		// iptables (vmap dispatch), so this count legitimately differs.
		w = chainWeight(req, "nftables", func(l string) bool { return strings.HasPrefix(l, "  ") })
	case "hns", "windows":
		w = hnsWeight(req)
	default:
		// iptables append rules are the "-A" lines.
		w = chainWeight(req, "iptables", func(l string) bool { return strings.HasPrefix(l, "-A ") })
	}
	// Peer breadth is dataplane-independent (same calc graph feeds every
	// render), so it's computed once and attached to whichever weight we built.
	w.PeerEntries, w.IPSets = peerBreadth(req)
	return w
}

// peerBreadth is the dataplane-independent peer-breadth cost read from the calc
// graph, on two axes:
//
//   - entries — total members the policy set's selectors/nets resolve to. A
//     loose PEER selector inflates this (and the programming update it drives)
//     while leaving rule counts flat.
//   - sets — the number of distinct IP sets. Every source/destination selector
//     is rendered as its own IP set (a separate dataplane object with fixed
//     per-set overhead), so many small selectors cost more to program and hold
//     than one broad one even at equal entry counts.
//
// Both materialise differently downstream (IP sets on iptables/nftables,
// inlined addresses in HNS ACLs, the eBPF map) but come from one graph.
func peerBreadth(req Request) (entries, sets int) {
	req, _ = applyInlineResources(req)
	g := buildGraph(req, nil)
	for _, members := range g.ipSetMembers {
		entries += len(members)
	}
	return entries, len(g.ipSetMembers)
}

// maxPoliciesPerEndpoint is the count of distinct policies that land on the
// busiest endpoint — the "how much work to determine which policies match this
// endpoint" cost. A policy with both ingress and egress rules is one policy,
// so it is deduped across directions and tiers.
func maxPoliciesPerEndpoint(wepByID map[string]*proto.WorkloadEndpoint) int {
	max := 0
	for _, w := range wepByID {
		seen := map[string]struct{}{}
		for _, t := range w.GetTiers() {
			for _, p := range t.GetIngressPolicies() {
				seen[t.GetName()+"/"+p.GetNamespace()+"/"+p.GetName()] = struct{}{}
			}
			for _, p := range t.GetEgressPolicies() {
				seen[t.GetName()+"/"+p.GetNamespace()+"/"+p.GetName()] = struct{}{}
			}
		}
		if len(seen) > max {
			max = len(seen)
		}
	}
	return max
}

// chainWeight renders the policy/endpoint/profile chains for one backend
// (static top-level chains excluded) and counts the rule lines isRule matches,
// summed over the IP versions present.
func chainWeight(req Request, backend string, isRule func(string) bool) *api.DataplaneWeight {
	resp := RenderIptables(req, IptablesOptions{
		Backends:      []string{backend},
		IncludeStatic: false,
	})
	rules := 0
	for _, dp := range resp.Dataplanes {
		for _, t := range dp.Tables {
			for _, c := range t.Chains {
				for _, line := range c.Lines {
					if isRule(line) {
						rules++
					}
				}
			}
		}
	}
	return &api.DataplaneWeight{Kind: backend, Rules: rules, RulesUnit: "rules"}
}

// hnsWeight counts the flattened HNS ACL rules Felix would install per endpoint
// × direction on Windows — the priority-rewritten list HNS actually receives
// after tier flattening. ByEndpoint attributes the total to each endpoint.
func hnsWeight(req Request) *api.DataplaneWeight {
	resp := RenderHNS(req, HNSOptions{})
	rules := 0
	byEndpoint := map[string]int{}
	for _, ep := range resp.Endpoints {
		rules += len(ep.Rules)
		byEndpoint[ep.Endpoint] += len(ep.Rules)
	}
	return &api.DataplaneWeight{Kind: "hns", Rules: rules, RulesUnit: "acl-rules", ByEndpoint: byEndpoint}
}

// bpfWeight measures the eBPF policy program cost: the instruction count Felix
// would JIT per endpoint × direction × IP version (the steady-state per-packet
// program). Selector breadth does NOT live here — it's in the eBPF map, which
// costDataplane records as PeerEntries — so Rules reflects program structure
// and the number of programs (applied breadth), PeerEntries the map footprint.
func bpfWeight(req Request) *api.DataplaneWeight {
	resp := RenderBPF(req, BPFOptions{})
	insns := 0
	byEndpoint := map[string]int{}
	for _, p := range resp.Programs {
		insns += p.Instructions
		byEndpoint[p.Endpoint] += p.Instructions
	}
	return &api.DataplaneWeight{Kind: "ebpf", Rules: insns, RulesUnit: "instructions", ByEndpoint: byEndpoint}
}
