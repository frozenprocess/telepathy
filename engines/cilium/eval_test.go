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
			if got := resp.Matrix[k]; got != want {
				t.Errorf("port %d: %s = %q, want %q", tc.port, k, got, want)
			}
		}
	}
}
