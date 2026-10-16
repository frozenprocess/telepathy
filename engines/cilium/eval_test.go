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

package main

import (
	"strings"
	"testing"

	"github.com/frozenprocess/telepathy/api"
)

// TestEvaluateIngressIsolation drives a real Cilium pkg/policy evaluation: a
// policy selecting role=backend that admits role=frontend on TCP/6379. backend
// becomes ingress-isolated; frontend and other are not selected by any policy,
// so traffic *to* them is unrestricted. Verifies the two-sided verdict and that
// the port matters (6379 opens, 80 does not).
func TestEvaluateIngressIsolation(t *testing.T) {
	np := "apiVersion: networking.k8s.io/v1\n" +
		"kind: NetworkPolicy\n" +
		"metadata:\n  name: allow-frontend\n  namespace: myns\n" +
		"spec:\n  podSelector:\n    matchLabels:\n      role: backend\n" +
		"  ingress:\n  - from:\n    - podSelector:\n        matchLabels:\n          role: frontend\n" +
		"    ports:\n    - protocol: TCP\n      port: 6379\n"

	req := api.Request{
		Endpoints: []api.Endpoint{
			{ID: "myns/frontend", Namespace: "myns", Name: "frontend", Labels: map[string]string{"role": "frontend"}},
			{ID: "myns/backend", Namespace: "myns", Name: "backend", Labels: map[string]string{"role": "backend"}},
			{ID: "myns/other", Namespace: "myns", Name: "other", Labels: map[string]string{"role": "other"}},
		},
		Namespaces: []api.NamespaceInput{{Name: "myns"}},
		Policies:   []api.PolicyInput{{Flavor: "k8s", YAML: np}},
		Protocol:   "tcp",
	}

	// Expected verdicts keyed by "src->dst"; anything not listed is not asserted.
	cases := []struct {
		port int
		want map[string]string
	}{
		{port: 6379, want: map[string]string{
			"myns/frontend->myns/backend": "allow", // admitted peer on the open port
			"myns/other->myns/backend":    "deny",  // wrong peer
			"myns/backend->myns/frontend": "allow", // frontend not isolated
		}},
		{port: 80, want: map[string]string{
			"myns/frontend->myns/backend": "deny", // right peer, wrong port
			"myns/other->myns/backend":    "deny",
			"myns/backend->myns/other":    "allow", // other not isolated
		}},
	}

	for _, tc := range cases {
		req.Port = tc.port
		resp := evaluate(req)
		if len(resp.Errors) != 0 {
			t.Fatalf("port %d: unexpected errors: %v", tc.port, resp.Errors)
		}
		for k, want := range tc.want {
			from, to, _ := strings.Cut(k, "->")
			selected := req
			selected.MatrixPairs = []api.MatrixPair{{From: from, To: to}, {From: "missing", To: to}, {From: from, To: from}}
			partial := evaluate(selected)
			if len(partial.Matrix) != 1 || partial.Matrix[k] != want {
				t.Fatalf("partial matrix: %v, want %s=%s", partial.Matrix, k, want)
			}

			if got := resp.Matrix[k]; got != want {
				t.Errorf("port %d: %s = %q, want %q", tc.port, k, got, want)
			}
		}
	}
}

// TestEvaluateEgressCIDR guards the CIDR-peer resolution: an off-cluster peer
// (Role "external") is given a world+cidr identity, so a toCIDR rule matches it
// via Cilium's own prefix-containment (1.1.1.1 ∈ 1.1.1.0/24), while an
// in-cluster pod outside the CIDR is denied. Regression test for the false DENY
// where a peer's IP was never resolved to a CIDR identity.
func TestEvaluateEgressCIDR(t *testing.T) {
	cnp := "apiVersion: cilium.io/v2\n" +
		"kind: CiliumNetworkPolicy\n" +
		"metadata:\n  name: fe-egress-cidr\n  namespace: demo\n" +
		"spec:\n  endpointSelector:\n    matchLabels:\n      role: frontend\n" +
		"  egress:\n  - toCIDR:\n    - 1.1.1.0/24\n"

	req := api.Request{
		Endpoints: []api.Endpoint{
			{ID: "demo/frontend", Namespace: "demo", Name: "frontend", IP: "10.0.0.1", Labels: map[string]string{"role": "frontend"}},
			{ID: "demo/backend", Namespace: "demo", Name: "backend", IP: "10.0.0.2", Labels: map[string]string{"role": "backend"}},
			{ID: "world/internet", Namespace: "world", Name: "internet", IP: "1.1.1.1", Labels: map[string]string{"scope": "internet"}, Role: "external", Unpoliced: true},
		},
		Namespaces: []api.NamespaceInput{{Name: "demo"}},
		Policies:   []api.PolicyInput{{Flavor: "cilium", YAML: cnp}},
		Protocol:   "tcp",
		Port:       8080,
	}

	resp := evaluate(req)
	if len(resp.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", resp.Errors)
	}
	want := map[string]string{
		"demo/frontend->world/internet": "allow", // IP inside the allowed CIDR
		"demo/frontend->demo/backend":   "deny",  // in-cluster pod, outside the CIDR
	}
	for k, w := range want {
		if got := resp.Matrix[k]; got != w {
			t.Errorf("%s = %q, want %q", k, got, w)
		}
	}
}

// Egress named ports use the destination endpoint's declared port map through
// Repository.SetNamedPortsGetter; Flow.NamedPortsTCP/UDP alone only covers ingress.
func TestEvaluateEgressNamedPort(t *testing.T) {
	req := api.Request{
		Namespaces: []api.NamespaceInput{{Name: "demo"}},
		Endpoints: []api.Endpoint{
			{ID: "demo/frontend", Namespace: "demo", Name: "frontend", Labels: map[string]string{"role": "frontend"}},
			{ID: "demo/backend", Namespace: "demo", Name: "backend", Labels: map[string]string{"role": "backend"}, Ports: []api.EndpointPort{{Name: "web", Port: 8080, Protocol: "tcp"}}},
		},
		Policies: []api.PolicyInput{{YAML: `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: frontend-egress, namespace: demo}
spec:
  endpointSelector: {matchLabels: {role: frontend}}
  egress:
  - toEndpoints: [{matchLabels: {role: backend}}]
    toPorts:
    - ports: [{port: web, protocol: TCP}]
`}},
		Protocol: "tcp",
	}
	for port, want := range map[int]string{8080: "allow", 9090: "deny"} {
		req.Port = port
		resp := evaluate(req)
		if len(resp.Errors) > 0 {
			t.Fatalf("port %d errors: %v", port, resp.Errors)
		}
		if got := resp.Matrix["demo/frontend->demo/backend"]; got != want {
			t.Errorf("port %d: got %q, want %q", port, got, want)
		}
	}
}
