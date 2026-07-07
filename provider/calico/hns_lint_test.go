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
	"testing"
)

// TestHNSLintWarnsOnDroppedRules: a policy using a negative match (notNets) or
// notProtocol renders to a Windows ACL list with that rule silently dropped, so
// RenderHNS must emit a warning naming the divergence. A rule with no corner
// case must NOT warn (non-vacuous).
func TestHNSLintWarnsOnDroppedRules(t *testing.T) {
	req := Request{
		Namespaces: []NamespaceInput{{Name: "ns", Labels: map[string]string{"name": "ns"}}},
		Endpoints: []Endpoint{
			{ID: "ns/a", Namespace: "ns", Name: "a", IP: "10.0.0.1", Labels: map[string]string{"app": "a"}},
		},
		Port:     8080,
		Protocol: "tcp",
		Policies: []PolicyInput{{YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: notnets-deny}
spec:
  selector: app == "a"
  types: [Egress]
  egress:
  - action: Deny
    destination:
      nets: ["0.0.0.0/0"]
      notNets: ["10.0.0.3/32"]
`}, {YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: notproto-deny}
spec:
  selector: app == "a"
  types: [Ingress]
  ingress:
  - action: Deny
    notProtocol: UDP
`}, {YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: plain-allow}
spec:
  selector: app == "a"
  types: [Ingress]
  ingress:
  - action: Allow
    protocol: TCP
`}, {YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: default-tier-pass}
spec:
  selector: app == "a"
  types: [Ingress]
  ingress:
  - action: Pass
`}},
	}

	resp := RenderHNS(req, HNSOptions{})
	joined := strings.Join(resp.Warnings, "\n")

	for _, want := range []string{"notnets-deny", "notNets", "notproto-deny", "notProtocol", "default-tier-pass", "Pass-action"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected warning to mention %q; got:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "plain-allow") {
		t.Errorf("plain Allow/TCP rule must not warn; got:\n%s", joined)
	}
}

// TestHNSLintPassInCustomTierNoWarn: a Pass rule in a NON-default tier flattens
// into the next tier and is faithful, so it must NOT warn (only a terminal /
// default-tier Pass diverges).
func TestHNSLintPassInCustomTierNoWarn(t *testing.T) {
	req := Request{
		Namespaces: []NamespaceInput{{Name: "ns", Labels: map[string]string{"name": "ns"}}},
		Endpoints: []Endpoint{
			{ID: "ns/a", Namespace: "ns", Name: "a", IP: "10.0.0.1", Labels: map[string]string{"app": "a"}},
		},
		Port:     8080,
		Protocol: "tcp",
		Policies: []PolicyInput{{YAML: `
apiVersion: projectcalico.org/v3
kind: Tier
metadata: {name: sec}
spec: {order: 100}
`}, {YAML: `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: sec.custom-pass}
spec:
  tier: sec
  selector: app == "a"
  types: [Ingress]
  ingress:
  - action: Pass
`}},
	}

	resp := RenderHNS(req, HNSOptions{})
	if joined := strings.Join(resp.Warnings, "\n"); strings.Contains(joined, "custom-pass") {
		t.Errorf("Pass in a non-default tier must not warn; got:\n%s", joined)
	}
}

// cnpReq builds a Request with prod/dev namespaces + one prod pod, plus the
// given ClusterNetworkPolicy YAMLs (each its own PolicyInput — the feed reads
// one doc per input).
func cnpReq(policyYAMLs ...string) Request {
	pols := make([]PolicyInput, len(policyYAMLs))
	for i, y := range policyYAMLs {
		pols[i] = PolicyInput{YAML: y}
	}
	return Request{
		Namespaces: []NamespaceInput{
			{Name: "prod", Labels: map[string]string{"env": "prod"}},
			{Name: "dev", Labels: map[string]string{"env": "dev"}},
		},
		Endpoints: []Endpoint{
			{ID: "prod/a", Namespace: "prod", Name: "a", IP: "10.0.0.1", Labels: map[string]string{"app": "a"}},
		},
		Port:     8080,
		Protocol: "tcp",
		Policies: pols,
	}
}

// TestHNSLintAdminTierPassNoWarn: a ClusterNetworkPolicy in the Admin tier maps
// to the "kube-admin" tier, which is evaluated FIRST (non-terminal). Its Pass
// flattens into the lower tiers/profile on Windows exactly as on Linux, so it
// is faithful and must NOT raise a tier-pass-block warning. (Only a Pass in the
// terminal tier diverges — see TestHNSLintWarnsOnDroppedRules's default case.)
func TestHNSLintAdminTierPassNoWarn(t *testing.T) {
	req := cnpReq(`
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata: {name: admin-pass}
spec:
  tier: Admin
  priority: 10
  subject:
    namespaces:
      matchLabels: {env: prod}
  ingress:
    - name: pass-from-dev
      action: Pass
      from:
        - namespaces:
            matchLabels: {env: dev}
`)
	if joined := strings.Join(RenderHNS(req, HNSOptions{}).Warnings, "\n"); strings.Contains(joined, "Pass-action") {
		t.Errorf("Admin-tier Pass is non-terminal and faithful; must not warn. got:\n%s", joined)
	}
}

// TestHNSLintBaselineTierPassNoWarn: a ClusterNetworkPolicy in the Baseline
// tier maps to "kube-baseline", the lowest tier. When it is the only policy the
// namespace profile is appended AFTER it, so its Pass flattens into the profile
// (allow) on both dataplanes — faithful, must NOT warn. A baseline Pass only
// becomes a terminal-tier divergence when a higher tier Passes into it, and
// that upstream Pass is itself flagged (it lives in the default tier).
func TestHNSLintBaselineTierPassNoWarn(t *testing.T) {
	req := cnpReq(`
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata: {name: baseline-pass}
spec:
  tier: Baseline
  priority: 100
  subject:
    namespaces:
      matchLabels: {env: prod}
  ingress:
    - name: pass-from-dev
      action: Pass
      from:
        - namespaces:
            matchLabels: {env: dev}
`)
	if joined := strings.Join(RenderHNS(req, HNSOptions{}).Warnings, "\n"); strings.Contains(joined, "Pass-action") {
		t.Errorf("Baseline-tier Pass flattens into the profile and is faithful; must not warn. got:\n%s", joined)
	}
}
