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

import (
	"strings"
	"testing"
)

// hepCommonInputs returns the boilerplate every test case shares: two pods
// (a/b) plus one HEP "gw" with a fixed IP and matching node. Tests layer
// policies on top to exercise the four HEP hooks; keeping the topology
// constant makes verdict diffs trace back to the policy under test.
func hepCommonInputs() Request {
	return Request{
		Namespaces: []NamespaceInput{
			{Name: "ns", Labels: map[string]string{"name": "ns"}},
		},
		Endpoints: []Endpoint{
			{ID: "ns/a", Namespace: "ns", Name: "a", IP: "10.0.0.1",
				Labels: map[string]string{"app": "a"}, Node: "n1"},
			{ID: "ns/b", Namespace: "ns", Name: "b", IP: "10.0.0.2",
				Labels: map[string]string{"app": "b"}, Node: "n1"},
		},
		HostEndpoints: []HostEndpointInput{
			{Name: "gw", Node: "n1", ExpectedIPs: []string{"192.168.0.1"},
				Labels: map[string]string{"role": "gateway"}},
		},
		Port:     8080,
		Protocol: "tcp",
	}
}

// TestHEPAppearsInMatrix is the phase-1 smoke test: a HEP without any policy
// shows up as both row and column, and its default-deny semantics (HEPs lack
// the per-namespace allow profile we stamp on workloads) deny every flow it
// participates in.
func TestHEPAppearsInMatrix(t *testing.T) {
	req := hepCommonInputs()
	resp := Evaluate(req)
	for _, err := range resp.Errors {
		t.Fatalf("unexpected error: %s", err)
	}

	wantPairs := []string{
		"ns/a->ns/b", "ns/b->ns/a",
		"ns/a->host/gw", "ns/b->host/gw",
		"host/gw->ns/a", "host/gw->ns/b",
	}
	for _, p := range wantPairs {
		if _, ok := resp.Matrix[p]; !ok {
			t.Errorf("matrix missing pair %q; got %v", p, keysOf(resp.Matrix))
		}
	}
	// Workload↔workload still allows (default-allow profile); HEP rows/cols
	// default-deny because there's no policy selecting the HEP.
	mustVerdict(t, resp, "ns/a->ns/b", "allow")
	mustVerdict(t, resp, "ns/a->host/gw", "deny")
	mustVerdict(t, resp, "host/gw->ns/a", "deny")
}

// TestApplyOnForwardGatesTransitFlows confirms applyOnForward fires for
// workload→workload flows whose Node matches the HEP's, even when the HEP
// itself is neither src nor dst.
func TestApplyOnForwardGatesTransitFlows(t *testing.T) {
	// Deny-all applyOnForward on the gateway HEP — should drop a↔b transit.
	denyAllForward := `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: deny-forward}
spec:
  selector: role == "gateway"
  applyOnForward: true
  types: [Ingress, Egress]
  ingress: [{action: Deny}]
  egress:  [{action: Deny}]
`
	req := hepCommonInputs()
	req.Policies = []PolicyInput{{YAML: denyAllForward}}
	resp := Evaluate(req)
	for _, err := range resp.Errors {
		t.Fatalf("unexpected error: %s", err)
	}
	// Forward-tier deny gates pod↔pod through the HEP's node.
	mustVerdict(t, resp, "ns/a->ns/b", "deny")
	mustVerdict(t, resp, "ns/b->ns/a", "deny")
}

// TestApplyOnForwardScopedByNode confirms a HEP on a *different* node does
// not affect flows whose endpoints are elsewhere — the overlay is keyed on
// node membership, not "all flows".
func TestApplyOnForwardScopedByNode(t *testing.T) {
	denyAllForward := `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: deny-forward}
spec:
  selector: role == "gateway"
  applyOnForward: true
  types: [Ingress, Egress]
  ingress: [{action: Deny}]
  egress:  [{action: Deny}]
`
	req := hepCommonInputs()
	// Move the HEP to n2 — neither workload lives there, so the forward
	// overlay should not fire for a↔b.
	req.HostEndpoints[0].Node = "n2"
	req.Policies = []PolicyInput{{YAML: denyAllForward}}
	resp := Evaluate(req)
	mustVerdict(t, resp, "ns/a->ns/b", "allow")
}

// TestPreDNATGatesIngressOnly confirms preDNAT applies as an ingress hook on
// the destination node's HEP. Same policy text without preDNAT would deny
// egress at the gateway too; here we verify only the dest-side check fires.
func TestPreDNATGatesIngressOnly(t *testing.T) {
	denyIngressPreDNAT := `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: deny-pre-dnat}
spec:
  selector: role == "gateway"
  preDNAT: true
  applyOnForward: true
  types: [Ingress]
  ingress: [{action: Deny}]
`
	req := hepCommonInputs()
	req.Policies = []PolicyInput{{YAML: denyIngressPreDNAT}}
	resp := Evaluate(req)
	for _, err := range resp.Errors {
		t.Fatalf("unexpected error: %s", err)
	}
	// preDNAT is dest-side ingress only — a→b goes through gw's preDNAT
	// ingress, so it denies. b→a likewise.
	mustVerdict(t, resp, "ns/a->ns/b", "deny")
	mustVerdict(t, resp, "ns/b->ns/a", "deny")
}

// TestDoNotTrackSymmetric exercises the "reply leg must also be allowed"
// property: a one-direction-only allow on the HEP's untracked tier should
// NOT permit the connection, because untracked traffic has no conntrack.
func TestDoNotTrackSymmetric(t *testing.T) {
	// Allow only the forward direction (egress out of the HEP, equivalently
	// ingress to clients) — the reverse leg has no matching rule and the
	// tier's default-deny kicks in for it.
	oneWayUntracked := `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: untracked-egress-only}
spec:
  selector: role == "gateway"
  doNotTrack: true
  applyOnForward: true
  types: [Egress]
  egress: [{action: Allow}]
`
	req := hepCommonInputs()
	req.Policies = []PolicyInput{{YAML: oneWayUntracked}}
	resp := Evaluate(req)
	for _, err := range resp.Errors {
		t.Fatalf("unexpected error: %s", err)
	}
	// HEP-as-src: forward leg (egress) allows, reverse leg (ingress) hits
	// the tier default-deny because there's no ingress rule. Connection
	// denied — this is the doNotTrack semantics we want to model.
	mustVerdict(t, resp, "host/gw->ns/a", "deny")
}

// TestHEPWithoutExpectedIPs verifies the corner case: a HEP with no IPs is
// excluded from rows/cols but its forward/preDNAT tiers still gate flows
// through its node. The warning surfaces in Response.Warnings so dataset
// authors notice the asymmetry.
func TestHEPWithoutExpectedIPs(t *testing.T) {
	req := hepCommonInputs()
	req.HostEndpoints[0].ExpectedIPs = nil
	req.Policies = []PolicyInput{{YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: deny-forward}
spec:
  selector: role == "gateway"
  applyOnForward: true
  types: [Ingress, Egress]
  ingress: [{action: Deny}]
  egress:  [{action: Deny}]
`}}
	resp := Evaluate(req)
	if _, ok := resp.Matrix["ns/a->host/gw"]; ok {
		t.Errorf("HEP without ExpectedIPs should not appear in matrix, got entry for ns/a->host/gw")
	}
	// But its forward overlay still gates pod↔pod on its node.
	mustVerdict(t, resp, "ns/a->ns/b", "deny")
	// And we warn about it so dataset authors see the asymmetry.
	if !anyContains(resp.Warnings, "no ExpectedIPs") {
		t.Errorf("expected ExpectedIPs warning, got %v", resp.Warnings)
	}
}

func mustVerdict(t *testing.T, resp Response, pair, want string) {
	t.Helper()
	got, ok := resp.Matrix[pair]
	if !ok {
		t.Errorf("matrix missing %q (have %v)", pair, keysOf(resp.Matrix))
		return
	}
	if got != want {
		t.Errorf("%s: got %q, want %q", pair, got, want)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func anyContains(xs []string, needle string) bool {
	for _, x := range xs {
		if strings.Contains(x, needle) {
			return true
		}
	}
	return false
}
