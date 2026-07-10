// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Telepathy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License").

package api

import "testing"

func TestComputeCost(t *testing.T) {
	// One broad k8s policy with a duplicated egress rule and an ipBlock; one
	// tight Calico GNP with a negation. NetworkSet must be ignored.
	req := Request{Policies: []PolicyInput{
		{YAML: `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-all-egress, namespace: demo}
spec:
  podSelector: {}
  egress:
  - to: [{ipBlock: {cidr: 10.0.0.0/8}}]
  - to: [{ipBlock: {cidr: 10.0.0.0/8}}]
`},
		{YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: db-only}
spec:
  selector: app == 'db'
  ingress:
  - action: Allow
    source: {selector: app == 'web', notNets: [169.254.0.0/16]}
`},
		{YAML: `
apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata: {name: ignore-me}
spec:
  nets: [1.2.3.4/32, 5.6.7.8/32]
`},
	}}

	r := ComputeCost(req)

	if r.Structural.Policies != 2 {
		t.Errorf("policies = %d, want 2 (NetworkSet excluded)", r.Structural.Policies)
	}
	if r.Structural.Rules != 3 { // 2 egress + 1 ingress
		t.Errorf("rules = %d, want 3", r.Structural.Rules)
	}
	if r.Structural.CIDRs != 3 { // two ipBlock.cidr + one notNets entry
		t.Errorf("cidrs = %d, want 3", r.Structural.CIDRs)
	}
	if r.Structural.Negations != 1 { // notNets
		t.Errorf("negations = %d, want 1", r.Structural.Negations)
	}

	// One broad-selector (empty podSelector) + one duplicate-rule.
	codes := map[string]int{}
	for _, f := range r.Hygiene {
		codes[f.Code]++
	}
	if codes["broad-selector"] != 1 || codes["duplicate-rule"] != 1 {
		t.Errorf("hygiene codes = %v, want one broad-selector + one duplicate-rule", codes)
	}

	// Cost = rules*2 + cidrs*1 + negs*3 + broad(10) + dup(5) = 6+3+3+10+5 = 27.
	if r.Cost != 27 {
		t.Errorf("cost = %d, want 27", r.Cost)
	}
	if r.Dataplane != nil {
		t.Errorf("portable core must not fill Dataplane")
	}
}

func TestBroadSelectorRefinement(t *testing.T) {
	broadCount := func(yaml string) int {
		n := 0
		for _, f := range ComputeCost(Request{Policies: []PolicyInput{{YAML: yaml}}}).Hygiene {
			if f.Code == "broad-selector" {
				n++
			}
		}
		return n
	}

	// FLAG: all() applied selector that allows a specific peer (the doc's case).
	if got := broadCount(`
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: over-scoped}
spec:
  selector: all()
  ingress:
  - action: Allow
    source: {selector: 'app == "web"'}
`); got != 1 {
		t.Errorf("over-scoped allow: broad-selector findings = %d, want 1", got)
	}

	// EXEMPT: broad default-deny (no allow rules) — doc-endorsed use of all().
	if got := broadCount(`
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: default-deny}
spec:
  selector: all()
  types: [Ingress, Egress]
`); got != 0 {
		t.Errorf("default-deny: broad-selector findings = %d, want 0", got)
	}

	// EXEMPT: broad deny-list (only Deny rules) — doc-endorsed use of all().
	if got := broadCount(`
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: deny-list}
spec:
  selector: all()
  ingress:
  - action: Deny
    source: {selector: 'threat == "true"'}
`); got != 0 {
		t.Errorf("deny-list: broad-selector findings = %d, want 0", got)
	}
}

func TestRulePerfFindings(t *testing.T) {
	codes := func(yaml string) map[string]int {
		m := map[string]int{}
		for _, f := range ComputeCost(Request{Policies: []PolicyInput{{YAML: yaml}}}).Hygiene {
			m[f.Code]++
		}
		return m
	}

	// #2 unreachable: a match-all Allow that isn't last shadows the rule after it.
	// #3 log-action: the trailing rule uses action: Log.
	c := codes(`
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: shadowed}
spec:
  selector: app == "x"
  ingress:
  - action: Allow
  - action: Allow
    source: {selector: 'app == "web"'}
  - action: Log
`)
	if c["unreachable-rules"] != 1 {
		t.Errorf("want 1 unreachable-rules, got %v", c)
	}
	if c["log-action"] != 1 {
		t.Errorf("want 1 log-action, got %v", c)
	}

	// A match-all Log does NOT shadow (evaluation continues) — no finding.
	if c := codes(`
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: logfirst}
spec:
  selector: app == "x"
  ingress:
  - action: Log
  - action: Allow
    source: {selector: 'app == "web"'}
`); c["unreachable-rules"] != 0 {
		t.Errorf("match-all Log must not shadow, got %v", c)
	}

	// #1 ports: a large inline port list flags inline-ports and counts structurally.
	r := ComputeCost(Request{Policies: []PolicyInput{{YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: manyports}
spec:
  selector: app == "x"
  ingress:
  - action: Allow
    destination: {ports: [1,2,3,4,5,6,7,8,9,10]}
`}}})
	if r.Structural.Ports != 10 {
		t.Errorf("ports = %d, want 10", r.Structural.Ports)
	}
	got := 0
	for _, f := range r.Hygiene {
		if f.Code == "inline-ports" {
			got++
		}
	}
	if got != 1 {
		t.Errorf("want 1 inline-ports finding, got %d", got)
	}
}

func TestNetworkSetFindings(t *testing.T) {
	// A GNP with 6 inline CIDRs and a domains: list — both should flag.
	req := Request{Policies: []PolicyInput{{YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: egress-allow}
spec:
  selector: all()
  egress:
  - action: Allow
    destination:
      nets: [1.0.0.0/8, 2.0.0.0/8, 3.0.0.0/8, 4.0.0.0/8, 5.0.0.0/8, 6.0.0.0/8]
  - action: Allow
    destination:
      domains: ["api.example.com"]
`}}}
	codes := map[string]int{}
	for _, f := range ComputeCost(req).Hygiene {
		codes[f.Code]++
	}
	if codes["inline-cidrs"] != 1 {
		t.Errorf("want one inline-cidrs finding, got %v", codes)
	}
	if codes["inline-domains"] != 1 {
		t.Errorf("want one inline-domains finding, got %v", codes)
	}

	// Below threshold + no domains: no NetworkSet finding.
	few := Request{Policies: []PolicyInput{{YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: ok}
spec:
  selector: app == "x"
  egress:
  - action: Allow
    destination: {nets: [1.0.0.0/8, 2.0.0.0/8]}
`}}}
	for _, f := range ComputeCost(few).Hygiene {
		if f.Code == "inline-cidrs" || f.Code == "inline-domains" {
			t.Errorf("unexpected NetworkSet finding for a small policy: %+v", f)
		}
	}
}
