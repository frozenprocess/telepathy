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

import "testing"

// findTierMatch returns the TierMatch for endpoint id, or nil.
func findTierMatch(resp TierMatchResponse, id string) *TierMatch {
	for i := range resp.Endpoints {
		if resp.Endpoints[i].Endpoint == id {
			return &resp.Endpoints[i]
		}
	}
	return nil
}

func hasPolicy(tm *TierMatch, name string) bool {
	for _, p := range tm.Policies {
		if p.Name == name {
			return true
		}
	}
	return false
}

func hasTier(tm *TierMatch, name string) bool {
	for _, t := range tm.Tiers {
		if t == name {
			return true
		}
	}
	return false
}

// TestResolveTierMatchesIncludesHEP is the regression for the missing HEP: a HEP
// selected by a preDNAT GlobalNetworkPolicy living in a CUSTOM tier must appear
// in ResolveTierMatches with that policy and its real tier — a HEP is a GNP
// subject, not a tier of its own.
func TestResolveTierMatchesIncludesHEP(t *testing.T) {
	req := hepCommonInputs()
	req.Policies = []PolicyInput{
		{YAML: `
apiVersion: projectcalico.org/v3
kind: Tier
metadata: {name: edge}
spec: {order: 900000}
`},
		{YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: edge-prednat-deny}
spec:
  tier: edge
  selector: role == "gateway"
  preDNAT: true
  applyOnForward: true
  types: [Ingress]
  ingress: [{action: Deny}]
`},
	}
	resp := ResolveTierMatches(req)
	for _, e := range resp.Errors {
		t.Fatalf("unexpected error: %s", e)
	}
	tm := findTierMatch(resp, "host/gw")
	if tm == nil {
		t.Fatalf("HEP host/gw missing from tier matches; got %v", resp.Endpoints)
	}
	if !hasPolicy(tm, "edge-prednat-deny") {
		t.Errorf("host/gw should match edge-prednat-deny; policies=%v", tm.Policies)
	}
	if !hasTier(tm, "edge") {
		t.Errorf("host/gw should be subject to tier 'edge'; tiers=%v", tm.Tiers)
	}
}

// TestPreDNATBeatsHigherPriorityTier is the behaviour the user described: a
// preDNAT policy in a LOW-priority tier is evaluated before a normal policy in a
// HIGH-priority tier, because preDNAT is a pre-normal hook that fires regardless
// of tier order. Control (normal allow alone) is allow; adding the low-priority
// preDNAT deny flips a->b to deny.
func TestPreDNATBeatsHigherPriorityTier(t *testing.T) {
	tiers := `
apiVersion: projectcalico.org/v3
kind: Tier
metadata: {name: core}
spec: {order: 100}
---
apiVersion: projectcalico.org/v3
kind: Tier
metadata: {name: edge}
spec: {order: 900000}
`
	// Normal applyOnForward allow in the HIGH-priority 'core' tier (order 100):
	// on its own it lets forwarded a->b through the HEP.
	coreAllow := `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: core-forward-allow}
spec:
  tier: core
  selector: role == "gateway"
  applyOnForward: true
  types: [Ingress, Egress]
  ingress: [{action: Allow}]
  egress: [{action: Allow}]
`
	// preDNAT deny in the LOW-priority 'edge' tier (order 900000).
	edgePreDNATDeny := `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: edge-prednat-deny}
spec:
  tier: edge
  selector: role == "gateway"
  preDNAT: true
  applyOnForward: true
  types: [Ingress]
  ingress: [{action: Deny}]
`

	// Control: only the high-priority normal allow -> a->b permitted.
	ctrl := hepCommonInputs()
	ctrl.Policies = []PolicyInput{{YAML: tiers}, {YAML: coreAllow}}
	rc := Evaluate(ctrl)
	for _, e := range rc.Errors {
		t.Fatalf("control: unexpected error: %s", e)
	}
	mustVerdict(t, rc, "ns/a->ns/b", "allow")

	// Add the LOW-priority preDNAT deny: it is evaluated before the
	// high-priority normal tier, so a->b now denies.
	full := hepCommonInputs()
	full.Policies = []PolicyInput{{YAML: tiers}, {YAML: coreAllow}, {YAML: edgePreDNATDeny}}
	rf := Evaluate(full)
	for _, e := range rf.Errors {
		t.Fatalf("full: unexpected error: %s", e)
	}
	mustVerdict(t, rf, "ns/a->ns/b", "deny")
}

// TestResolveTierMatchesIncludesStaged: a StagedGlobalNetworkPolicy selects
// endpoints in the tier view even though the request leaves EvaluateStaged
// false (so the matrix wouldn't enforce it). Staged = visible but not enforced.
func TestResolveTierMatchesIncludesStaged(t *testing.T) {
	req := Request{
		Namespaces: []NamespaceInput{{Name: "prod", Labels: map[string]string{"name": "prod"}}},
		Endpoints: []Endpoint{{ID: "prod/backend", Namespace: "prod", Name: "backend",
			IP: "10.0.0.2", Labels: map[string]string{"app": "backend", "env": "prod"}, Node: "n1"}},
		Policies: []PolicyInput{{YAML: `
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata: {name: backend-lockdown-staged}
spec:
  selector: env == 'prod' && app == 'backend'
  types: [Ingress]
`}},
		Port: 8080, Protocol: "tcp",
		// EvaluateStaged deliberately left false.
	}
	r := ResolveTierMatches(req)
	tm := findTierMatch(r, "prod/backend")
	if tm == nil {
		t.Fatal("prod/backend missing from tier matches")
	}
	if !hasPolicy(tm, "backend-lockdown-staged") {
		t.Fatalf("staged policy should select prod/backend in the tier view; policies=%v", tm.Policies)
	}
}
