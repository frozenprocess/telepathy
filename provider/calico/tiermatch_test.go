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

func findMatch(resp TierMatchResponse, endpoint string) *TierMatch {
	for i := range resp.Endpoints {
		if resp.Endpoints[i].Endpoint == endpoint {
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

// TestResolveTierMatchesIncludesHEPForwardPolicy is the regression guard for the
// host-firewall tier view: an applyOnForward GNP selecting a HEP lives in the
// HEP's forward tiers (not GetTiers()), and HEPs weren't walked at all - so the
// tier view stayed blank for exactly the policies HEPs exist to carry. The HEP
// must appear (keyed "host/<name>") with the forward policy attributed to it.
func TestResolveTierMatchesIncludesHEPForwardPolicy(t *testing.T) {
	denyForward := `
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
	req.Policies = []PolicyInput{{YAML: denyForward}}

	resp := ResolveTierMatches(req)
	for _, e := range resp.Errors {
		t.Fatalf("unexpected error: %s", e)
	}

	tm := findMatch(resp, "host/gw")
	if tm == nil {
		t.Fatal("HEP host/gw absent from tier matches (regression: HEPs not resolved)")
	}
	if !hasPolicy(tm, "deny-forward") {
		t.Fatalf("applyOnForward policy not attributed to host/gw; got %+v", tm.Policies)
	}
	if len(tm.Tiers) == 0 {
		t.Fatalf("host/gw has a matching policy but no subject tier; got %+v", tm)
	}
}
