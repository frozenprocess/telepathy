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
	"testing"

	"github.com/frozenprocess/telepathy/api"
)

// These exercise the evaluator's harder paths over Antrea's real selector
// engine: ingress label match, deny-all isolation, egress isolation,
// namespaceSelector, ipBlock, and named-port resolution. The root module
// additionally cross-checks the engine against the Calico provider end-to-end
// (TestEngineAgreesWithCalico).
func TestAntreaEvaluator(t *testing.T) {
	k8s := func(yaml string) api.PolicyInput { return api.PolicyInput{Flavor: "k8s", YAML: yaml} }
	base := func(policies ...api.PolicyInput) api.Request {
		return api.Request{
			Port: 8080, Protocol: "tcp",
			Namespaces: []api.NamespaceInput{
				{Name: "demo", Labels: map[string]string{"kubernetes.io/metadata.name": "demo"}},
				{Name: "prod", Labels: map[string]string{"kubernetes.io/metadata.name": "prod", "tier": "prod"}},
			},
			Endpoints: []api.Endpoint{
				{ID: "demo/frontend", Namespace: "demo", Name: "frontend", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}, Ports: []api.EndpointPort{{Name: "http", Port: 8080, Protocol: "tcp"}}},
				{ID: "demo/backend", Namespace: "demo", Name: "backend", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}, Ports: []api.EndpointPort{{Name: "http", Port: 8080, Protocol: "tcp"}}},
				{ID: "demo/attacker", Namespace: "demo", Name: "attacker", IP: "10.0.0.3", Labels: map[string]string{"app": "attacker"}},
				{ID: "prod/client", Namespace: "prod", Name: "client", IP: "10.0.1.1", Labels: map[string]string{"app": "client"}},
			},
			Policies: policies,
		}
	}

	cases := []struct {
		name string
		req  api.Request
		want map[string]string // subset of flows to assert
	}{
		{
			name: "ingress-allow-from-label",
			req: base(k8s(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: be-allow-fe, namespace: demo}
spec:
  podSelector: {matchLabels: {app: backend}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: frontend}}}]
      ports: [{protocol: TCP, port: 8080}]`)),
			want: map[string]string{
				"demo/frontend->demo/backend": "allow",
				"demo/attacker->demo/backend": "deny",
				"prod/client->demo/backend":   "deny",
				"demo/backend->demo/frontend": "allow",
			},
		},
		{
			name: "ingress-deny-all",
			req: base(k8s(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: be-deny, namespace: demo}
spec:
  podSelector: {matchLabels: {app: backend}}
  policyTypes: [Ingress]`)),
			want: map[string]string{
				"demo/frontend->demo/backend": "deny",
				"demo/attacker->demo/backend": "deny",
				"demo/backend->demo/frontend": "allow",
			},
		},
		{
			name: "egress-isolation-to-label",
			req: base(k8s(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: fe-egress-be, namespace: demo}
spec:
  podSelector: {matchLabels: {app: frontend}}
  policyTypes: [Egress]
  egress:
    - to: [{podSelector: {matchLabels: {app: backend}}}]`)),
			want: map[string]string{
				"demo/frontend->demo/backend":  "allow",
				"demo/frontend->demo/attacker": "deny",
				"demo/attacker->demo/frontend": "allow",
			},
		},
		{
			name: "ingress-namespace-selector",
			req: base(k8s(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: be-allow-prod, namespace: demo}
spec:
  podSelector: {matchLabels: {app: backend}}
  policyTypes: [Ingress]
  ingress:
    - from: [{namespaceSelector: {matchLabels: {tier: prod}}}]`)),
			want: map[string]string{
				"prod/client->demo/backend":   "allow",
				"demo/frontend->demo/backend": "deny",
				"demo/attacker->demo/backend": "deny",
			},
		},
		{
			name: "egress-ipblock",
			req: base(k8s(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: fe-egress-cidr, namespace: demo}
spec:
  podSelector: {matchLabels: {app: frontend}}
  policyTypes: [Egress]
  egress:
    - to: [{ipBlock: {cidr: 10.0.0.2/32}}]`)),
			want: map[string]string{
				"demo/frontend->demo/backend":  "allow",
				"demo/frontend->demo/attacker": "deny",
			},
		},
		{
			name: "ingress-named-port",
			req: base(k8s(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: be-allow-fe-named, namespace: demo}
spec:
  podSelector: {matchLabels: {app: backend}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: frontend}}}]
      ports: [{protocol: TCP, port: http}]`)),
			want: map[string]string{
				"demo/frontend->demo/backend": "allow", // named port "http" -> 8080
				"demo/attacker->demo/backend": "deny",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evaluate(tc.req)
			if len(resp.Errors) > 0 {
				t.Fatalf("errors: %v", resp.Errors)
			}
			for flow, want := range tc.want {
				if got := resp.Matrix[flow]; got != want {
					t.Errorf("%s: got %q, want %q", flow, got, want)
				}
			}
		})
	}
}
