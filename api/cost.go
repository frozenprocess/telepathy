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

package api

import (
	"encoding/json"
	"fmt"
	"strings"

	"sigs.k8s.io/yaml"
)

// A policy-efficiency ("performance") cost. The cost is a COST: lower is
// leaner. It has two layers, matching the pluggable-CNI seam:
//
//   - Structural + Hygiene — engine-INDEPENDENT, derived from the policy set
//     itself, so ComputeCost produces them for every provider (present or
//     future) with no engine code. This is the portable core.
//   - Dataplane — the exact compiled weight, filled only by an engine that can
//     render its own dataplane offline (Calico: iptables/eBPF; Cilium:
//     policy-map). nil when the engine can't (e.g. Antrea's OVS pipeline).
//
// The headline Cost is built ONLY from the portable layers, so two runs — or
// two engines — compare on the same footing. Dataplane.Unit is engine-defined
// and is compared within one engine only, never folded into Cost.
type CostReport struct {
	Engine         string           `json:"engine,omitempty"`
	Structural     Structural       `json:"structural"`
	Hygiene        []Finding        `json:"hygiene,omitempty"`
	Dataplane      *DataplaneWeight `json:"dataplane,omitempty"`
	Cost           int              `json:"cost"`
	FormulaVersion int              `json:"formulaVersion"`
}

// Structural is the engine-independent cost of a policy set. Rules/CIDRs/
// Negations are counted from the manifests; ResolvedPeers/MaxStack need
// selector resolution and are left zero by the portable core — an engine that
// already resolves selectors in Evaluate may fill them (see CostReport docs).
type Structural struct {
	Policies      int `json:"policies"`                // policy manifests that apply
	Rules         int `json:"rules"`                   // ingress+egress rules, all policies
	CIDRs         int `json:"cidrs"`                   // literal CIDRs (nets/notNets/ipBlock)
	Ports         int `json:"ports"`                   // literal port/notPort entries
	Negations     int `json:"negations"`               // not* matchers + ipBlock.except
	ResolvedPeers int `json:"resolvedPeers,omitempty"` // engine-supplied; selector breadth
	MaxStack      int `json:"maxStack,omitempty"`      // engine-supplied; policies on busiest endpoint
}

// Finding is one efficiency smell. Penalty is added to Cost.
type Finding struct {
	Policy  string `json:"policy"`
	Rule    int    `json:"rule,omitempty"`
	Code    string `json:"code"` // e.g. "broad-selector", "duplicate-rule"
	Detail  string `json:"detail"`
	Penalty int    `json:"penalty"`
}

// DataplaneWeight is an engine's real compiled cost, on two orthogonal axes:
//
//   - Rules — the programmed match cost the dataplane walks (iptables/nftables
//     chain rules, HNS ACL rules, eBPF instructions). Grows with the APPLIED
//     selector (how many endpoints the policy is programmed onto) and policy
//     structure. RulesUnit names the count.
//   - PeerEntries — the peer-breadth cost: the total members the policy's
//     selectors/nets resolve to. Grows with a loose PEER selector. This lives on
//     IP sets (iptables/nftables), inlined ACL addresses (HNS), or the eBPF map,
//     and it is what inflates the programming update when a broad selector churns.
//     It is computed from the calc graph and so is the SAME across dataplanes.
//
// Both are engine+dataplane-specific and comparable only within one dataplane
// across policy revisions — never across engines/dataplanes, never folded into
// Cost.
type DataplaneWeight struct {
	Kind        string         `json:"kind"`      // "iptables" | "nftables" | "ebpf" | "hns" | "policy-map"
	Rules       int            `json:"rules"`     // programmed match cost, in RulesUnit
	RulesUnit   string         `json:"rulesUnit"` // "rules" | "acl-rules" | "instructions"
	PeerEntries int            `json:"peerEntries"`
	IPSets      int            `json:"ipSets"`               // distinct IP sets (one per selector); per-set overhead is independent of size
	ByEndpoint  map[string]int `json:"byEndpoint,omitempty"` // Rules by endpoint, where attributable
}

// Cost weights, idea is the more you pack the heavier the cost.
// 0 is the best performance which means no policy at all.
const (
	costFormulaVersion = 2 // v2: added the Ports term

	weightRule = 2
	weightCIDR = 1
	weightPort = 1
	weightNeg  = 3

	penaltyBroadSelector = 10
	penaltyDuplicateRule = 5
	penaltyInlineNetSet  = 8
	penaltyUnreachable   = 6
	penaltyLogAction     = 4

	// A handful of inline CIDRs/ports is fine; a big list is the "putting a lot
	// of anything in policy (rules, CIDRs, ports) is inefficient" anti-pattern.
	cidrsInlineThreshold = 5
	portsInlineThreshold = 8
)

// ComputeCost computes the portable (engine-independent) efficiency cost for
// req's policy set. Engine and Dataplane are left for the caller/provider to
// fill; everything else is derived here from the manifests alone.
func ComputeCost(req Request) *CostReport {
	r := &CostReport{FormulaVersion: costFormulaVersion}
	for _, p := range req.Policies {
		var head struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(p.YAML), &head); err != nil || !isPolicyKind(head.Kind) {
			continue
		}
		var doc map[string]interface{}
		if err := yaml.Unmarshal([]byte(p.YAML), &doc); err != nil {
			continue
		}
		r.Structural.Policies++
		name := policyName(doc, head.Kind)
		spec, _ := doc["spec"].(map[string]interface{})

		for _, dir := range []string{"ingress", "egress"} {
			rules, _ := spec[dir].([]interface{})
			r.Structural.Rules += len(rules)
			r.Hygiene = append(r.Hygiene, duplicateRuleFindings(name, dir, rules)...)
			if f := unreachableRuleFinding(name, dir, rules); f != nil {
				r.Hygiene = append(r.Hygiene, *f)
			}
			if f := logActionFinding(name, dir, rules); f != nil {
				r.Hygiene = append(r.Hygiene, *f)
			}
		}

		cidrs, ports, negs := walkCounts(spec)
		r.Structural.CIDRs += cidrs
		r.Structural.Ports += ports
		r.Structural.Negations += negs

		if f := broadSelectorFinding(name, spec); f != nil {
			r.Hygiene = append(r.Hygiene, *f)
		}
		r.Hygiene = append(r.Hygiene, networkSetFindings(name, cidrs, strings.Contains(p.YAML, "domains:"))...)
		if ports >= portsInlineThreshold {
			r.Hygiene = append(r.Hygiene, Finding{Policy: name, Code: "inline-ports",
				Detail:  fmt.Sprintf("%d port entries — large port lists expand the match; use ranges or split the rule by need", ports),
				Penalty: penaltyInlineNetSet})
		}
	}
	r.Cost = costOf(r)
	return r
}

// costOf builds the headline number from the portable layers only.
func costOf(r *CostReport) int {
	s := r.Structural.Rules*weightRule +
		r.Structural.CIDRs*weightCIDR +
		r.Structural.Ports*weightPort +
		r.Structural.Negations*weightNeg
	for _, f := range r.Hygiene {
		s += f.Penalty
	}
	return s
}

// isPolicyKind is true for the policy manifests, false for topology/reference
// kinds (Tier, NetworkSet, HostEndpoint, Service, Profile). Every policy kind —
// NetworkPolicy, GlobalNetworkPolicy, ClusterNetworkPolicy, Staged*, and
// (Baseline)AdminNetworkPolicy — contains "NetworkPolicy"; NetworkSet does not.
func isPolicyKind(kind string) bool {
	return strings.Contains(kind, "NetworkPolicy")
}

func policyName(doc map[string]interface{}, kind string) string {
	if md, ok := doc["metadata"].(map[string]interface{}); ok {
		if n, ok := md["name"].(string); ok && n != "" {
			return kind + " " + n
		}
	}
	return kind
}

// walkCounts recurses the spec tree counting CIDR literals, port entries, and
// negation matchers. It is schema-agnostic (keys, not typed structs) so it
// covers k8s ipBlock, Calico nets/notNets/ports, and any future kind unchanged.
func walkCounts(node interface{}) (cidrs, ports, negs int) {
	switch v := node.(type) {
	case map[string]interface{}:
		for k, val := range v {
			switch k {
			case "nets", "notNets", "except": // CIDR lists
				if arr, ok := val.([]interface{}); ok {
					cidrs += len(arr)
				}
			case "cidr": // k8s ipBlock.cidr (single string)
				if _, ok := val.(string); ok {
					cidrs++
				}
			case "ports", "notPorts": // numeric/range/named port entries
				if arr, ok := val.([]interface{}); ok {
					ports += len(arr)
				}
			}
			if strings.HasPrefix(k, "not") || k == "except" {
				negs++
			}
			c, p, n := walkCounts(val)
			cidrs += c
			ports += p
			negs += n
		}
	case []interface{}:
		for _, item := range v {
			c, p, n := walkCounts(item)
			cidrs += c
			ports += p
			negs += n
		}
	}
	return
}

// Not sure this can get triggered, but its good to have a catch all.
func unreachableRuleFinding(name, dir string, rules []interface{}) *Finding {
	for i, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if i < len(rules)-1 && isMatchAll(rule) && isTerminalAction(rule) {
			return &Finding{Policy: name, Rule: i + 1, Code: "unreachable-rules",
				Detail: fmt.Sprintf("%s rule %d matches all traffic and terminates — the %d rule(s) after it are unreachable",
					dir, i+1, len(rules)-i-1),
				Penalty: penaltyUnreachable}
		}
	}
	return nil
}

// logActionFinding flags rules with action: Log, which logs every matching
// packet — a real per-packet throughput cost, and often left over from debugging.
func logActionFinding(name, dir string, rules []interface{}) *Finding {
	n := 0
	for _, r := range rules {
		if rule, ok := r.(map[string]interface{}); ok {
			if act, _ := rule["action"].(string); strings.EqualFold(act, "Log") {
				n++
			}
		}
	}
	if n == 0 {
		return nil
	}
	return &Finding{Policy: name, Code: "log-action",
		Detail:  fmt.Sprintf("%d %s rule(s) use action: Log — every matching packet is logged", n, dir),
		Penalty: penaltyLogAction}
}

// isMatchAll reports whether a rule has no match criteria at all (no peer,
// protocol, port, ICMP, HTTP or IP-version constraint) — it matches every packet.
func isMatchAll(rule map[string]interface{}) bool {
	for _, k := range []string{"source", "destination", "from", "to", "protocol",
		"notProtocol", "ports", "notPorts", "icmp", "notICMP", "http", "ipVersion", "serviceAccounts"} {
		switch vv := rule[k].(type) {
		case map[string]interface{}:
			if len(vv) > 0 {
				return false
			}
		case []interface{}:
			if len(vv) > 0 {
				return false
			}
		case nil:
			// absent — not a constraint
		default:
			return false // a scalar constraint (e.g. protocol: TCP)
		}
	}
	return true
}

// isTerminalAction reports whether a rule's action terminates evaluation for
// shadowing purposes: Calico Allow/Deny (Log/Pass continue), or a k8s rule
// (no action field — allow by nature).
func isTerminalAction(rule map[string]interface{}) bool {
	act, ok := rule["action"].(string)
	if !ok {
		return true
	}
	return strings.EqualFold(act, "Allow") || strings.EqualFold(act, "Deny")
}

// broadSelectorFinding flags a policy that applies to every pod it could — an
// empty k8s podSelector or a Calico all()/empty selector.
//
// Refinement (Tigera "10,000 workloads, but only 10 match label==foo"): a broad
// applied selector is only wasteful when the policy ALLOWS specific traffic —
// then it should be scoped to the workloads that actually need the rule. A broad
// default-deny (no allow rules) or deny-list (only Deny rules) is the
// doc-endorsed use of all() for cluster-wide scope, so it is NOT flagged.
func broadSelectorFinding(name string, spec map[string]interface{}) *Finding {
	scope := ""
	if ps, ok := spec["podSelector"].(map[string]interface{}); ok && len(ps) == 0 {
		scope = "empty podSelector applies to every pod in the namespace"
	}
	if sel, ok := spec["selector"].(string); ok {
		if s := strings.TrimSpace(sel); s == "" || s == "all()" {
			scope = fmt.Sprintf("selector %q applies to every endpoint in scope", sel)
		}
	}
	if scope == "" || !hasSpecificAllow(spec) {
		return nil
	}
	return &Finding{Policy: name, Code: "broad-selector",
		Detail:  scope + ", yet it only allows specific peers — scope the applied selector to the workloads that need the rule",
		Penalty: penaltyBroadSelector}
}

// hasSpecificAllow reports whether spec has at least one allow rule that
// constrains its peer (a selector/namespaceSelector/nets/cidr/domains/service
// account on source/destination or from/to). Calico Deny/Log/Pass rules are
// skipped (a deny-list is a fine use of a broad selector); k8s NetworkPolicy
// rules carry no action and are allow by nature.
func hasSpecificAllow(spec map[string]interface{}) bool {
	for _, dir := range []string{"ingress", "egress"} {
		rules, _ := spec[dir].([]interface{})
		for _, r := range rules {
			rule, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			if act, ok := rule["action"].(string); ok && !strings.EqualFold(act, "Allow") {
				continue
			}
			for _, peerKey := range []string{"source", "destination", "from", "to"} {
				if hasConstraintKey(rule[peerKey]) {
					return true
				}
			}
		}
	}
	return false
}

// hasConstraintKey reports whether a peer subtree names a label/CIDR/SA
// constraint — i.e. the rule targets specific peers rather than everything.
func hasConstraintKey(node interface{}) bool {
	switch v := node.(type) {
	case map[string]interface{}:
		for k, val := range v {
			switch k {
			case "selector", "namespaceSelector", "podSelector", "nets", "cidr",
				"domains", "serviceAccounts", "serviceAccountSelector":
				return true
			}
			if hasConstraintKey(val) {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if hasConstraintKey(item) {
				return true
			}
		}
	}
	return false
}

// networkSetFindings flags the inline-CIDR / inline-domain anti-pattern: a
// policy carrying many literal CIDRs, or any domains, that should live in a
// (Global)NetworkSet instead ("Put domains and CIDRs in network sets rather
// than policy"). NetworkSets are referenced by selector, so moving them there
// keeps the IP-set churn out of every policy update.
func networkSetFindings(name string, cidrs int, hasDomains bool) []Finding {
	var out []Finding
	if hasDomains {
		out = append(out, Finding{Policy: name, Code: "inline-domains",
			Detail:  "rules embed domains: — move them into a (Global)NetworkSet",
			Penalty: penaltyInlineNetSet})
	}
	if cidrs >= cidrsInlineThreshold {
		out = append(out, Finding{Policy: name, Code: "inline-cidrs",
			Detail:  fmt.Sprintf("%d inline CIDRs — move them into a (Global)NetworkSet rather than policy rules", cidrs),
			Penalty: penaltyInlineNetSet})
	}
	return out
}

// duplicateRuleFindings flags rules that exactly repeat an earlier rule in the
// same direction — dead weight the dataplane still has to carry. Equality is
// structural (canonical JSON), so it holds for both k8s and Calico rule shapes.
func duplicateRuleFindings(name, dir string, rules []interface{}) []Finding {
	var out []Finding
	seen := map[string]int{}
	for i, rule := range rules {
		b, err := json.Marshal(rule)
		if err != nil {
			continue
		}
		if j, ok := seen[string(b)]; ok {
			out = append(out, Finding{Policy: name, Rule: i + 1, Code: "duplicate-rule",
				Detail:  fmt.Sprintf("%s rule %d exactly duplicates rule %d", dir, i+1, j),
				Penalty: penaltyDuplicateRule})
			continue
		}
		seen[string(b)] = i + 1
	}
	return out
}
