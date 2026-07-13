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

const ingressDenyNoTypes = `
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata: {name: deny-ingress-b, namespace: ns}
spec:
  selector: app == "b"
  ingress:
  - action: Deny
`

// TestOmittedTypesDefaultsFromRules: a Calico policy with `types` omitted must
// behave as if the API server had defaulted it from the rules present (here
// ingress-only → [Ingress]). Pre-fix, the empty Types reached Felix's
// back-compat path, which treats it as Ingress+Egress, so the rule-less egress
// direction hit end-of-tier deny and b→a flipped to deny.
func TestOmittedTypesDefaultsFromRules(t *testing.T) {
	req := inlineCommonInputs()
	req.Policies = []PolicyInput{{YAML: ingressDenyNoTypes}}
	resp := Evaluate(req)
	for _, e := range resp.Errors {
		t.Fatalf("input error: %s", e)
	}
	mustVerdict(t, resp, "ns/a->ns/b", "deny")  // the ingress Deny still applies
	mustVerdict(t, resp, "ns/b->ns/a", "allow") // egress from b must be untouched
}
