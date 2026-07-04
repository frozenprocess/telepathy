// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Telepathy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// See the License for the specific language governing permissions and
// limitations under the License.

package calico

import "testing"

// TestEndOfTierFlowCount: a k8s NetworkPolicy selects pod a for ingress but its
// rule matches nobody, so every flow INTO a falls through the default tier to
// its end-of-tier deny (a partial match). Only b->a qualifies here, so the
// default tier's end-of-tier flow count is 1. a->b is decided elsewhere (b is
// unselected -> allowed by profile), contributing nothing.
func TestEndOfTierFlowCount(t *testing.T) {
	req := Request{
		Namespaces: []NamespaceInput{{Name: "ns", Labels: map[string]string{"name": "ns"}}},
		Endpoints: []Endpoint{
			{ID: "ns/a", Namespace: "ns", Name: "a", IP: "10.0.0.1", Labels: map[string]string{"app": "a"}, Node: "n1"},
			{ID: "ns/b", Namespace: "ns", Name: "b", IP: "10.0.0.2", Labels: map[string]string{"app": "b"}, Node: "n1"},
		},
		Policies: []PolicyInput{{Flavor: "k8s", YAML: `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: isolate-a, namespace: ns}
spec:
  podSelector: {matchLabels: {app: a}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: nonexistent}}}]
`}},
		Port:     8080,
		Protocol: "tcp",
	}
	// Sanity: matrix denies b->a, allows a->b.
	m := Evaluate(req)
	mustVerdict(t, m, "ns/b->ns/a", "deny")
	mustVerdict(t, m, "ns/a->ns/b", "allow")

	r := ResolveTierMatches(req)
	for _, e := range r.Errors {
		t.Fatalf("unexpected error: %s", e)
	}
	if got := r.EndOfTierFlows["default"]; got != 1 {
		t.Fatalf("default tier end-of-tier flow count = %d, want 1 (only b->a falls through); all=%v", got, r.EndOfTierFlows)
	}
}
