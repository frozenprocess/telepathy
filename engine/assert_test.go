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

import "testing"

// assertTopology is a three-pod namespace mirroring testdata: frontend and
// attacker both try to reach backend on 8080. The layered policy permits only
// app==frontend, so frontend->backend allows and attacker->backend denies —
// the canonical pass/fail pair the assertion engine must distinguish.
func assertTopology() Request {
	return Request{
		Namespaces: []NamespaceInput{{Name: "demo", Labels: map[string]string{"kubernetes.io/metadata.name": "demo"}}},
		Endpoints: []Endpoint{
			{ID: "demo/frontend", Namespace: "demo", Name: "frontend", IP: "10.0.0.1",
				Labels: map[string]string{"app": "frontend"},
				Ports:  []EndpointPort{{Name: "http", Port: 8080, Protocol: "tcp"}}},
			{ID: "demo/backend", Namespace: "demo", Name: "backend", IP: "10.0.0.2",
				Labels: map[string]string{"app": "backend"},
				Ports:  []EndpointPort{{Name: "http", Port: 8080, Protocol: "tcp"}}},
			{ID: "demo/attacker", Namespace: "demo", Name: "attacker", IP: "10.0.0.3",
				Labels: map[string]string{"app": "attacker"}},
		},
		Policies: []PolicyInput{{Flavor: "k8s", YAML: `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: backend-allow-frontend, namespace: demo}
spec:
  podSelector: {matchLabels: {app: backend}}
  policyTypes: [Ingress]
  ingress:
  - from: [{podSelector: {matchLabels: {app: frontend}}}]
    ports: [{protocol: TCP, port: 8080}]
`}},
		Port:     8080,
		Protocol: "tcp",
	}
}

// TestRunAssertionsPassFail: the expected-correct flow passes and the
// expected-correct deny passes, proving the engine reads both verdicts. Then a
// wrong expectation must fail — otherwise the check is vacuous.
func TestRunAssertionsPassFail(t *testing.T) {
	req := assertTopology()
	rep := RunAssertions(req, []Assertion{
		{Name: "frontend reaches backend", From: "demo/frontend", To: "demo/backend", Expect: "allow"},
		{Name: "attacker blocked", From: "demo/attacker", To: "demo/backend", Expect: "deny"},
	})
	if !rep.Ok() {
		t.Fatalf("expected all pass, got %d failed: %+v", rep.Failed, rep.Results)
	}
	if rep.Passed != 2 {
		t.Fatalf("expected 2 passed, got %d", rep.Passed)
	}

	// A deliberately wrong expectation must fail and report the real verdict.
	rep = RunAssertions(req, []Assertion{
		{From: "demo/attacker", To: "demo/backend", Expect: "allow"},
	})
	if rep.Ok() || rep.Failed != 1 {
		t.Fatalf("expected the wrong expectation to fail, got %+v", rep)
	}
	if rep.Results[0].Got != "deny" {
		t.Fatalf("expected Got=deny, got %q", rep.Results[0].Got)
	}
}

// TestRunAssertionsUnknownFlowAndBadExpect: a typo'd endpoint id and a bad
// expect value must each fail with an Err (not pass, not panic), since these
// are the most common authoring mistakes.
func TestRunAssertionsUnknownFlowAndBadExpect(t *testing.T) {
	req := assertTopology()
	rep := RunAssertions(req, []Assertion{
		{From: "demo/frontend", To: "demo/nope", Expect: "allow"},
		{From: "demo/frontend", To: "demo/backend", Expect: "maybe"},
	})
	if rep.Failed != 2 {
		t.Fatalf("expected 2 failures, got %d: %+v", rep.Failed, rep.Results)
	}
	for _, r := range rep.Results {
		if r.Err == "" {
			t.Fatalf("expected an Err for %+v", r.Assertion)
		}
	}
}

// TestDecodeAssertionsBothForms: the bare-list and the wrapped `assertions:`
// forms must decode identically, since the README advertises both.
func TestDecodeAssertionsBothForms(t *testing.T) {
	bare := []byte("- {from: a, to: b, expect: allow}\n- {from: a, to: c, expect: deny}\n")
	wrapped := []byte("assertions:\n  - {from: a, to: b, expect: allow}\n  - {from: a, to: c, expect: deny}\n")
	for _, in := range [][]byte{bare, wrapped} {
		got, err := DecodeAssertions(in)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != 2 || got[0].From != "a" || got[1].Expect != "deny" {
			t.Fatalf("unexpected parse: %+v", got)
		}
	}
	if _, err := DecodeAssertions([]byte("   ")); err == nil {
		t.Fatal("expected error on empty input")
	}
}
