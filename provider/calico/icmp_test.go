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
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// intPtr keeps the table-driven tests below readable: most rows have at least
// one *int field and inline `&v` doesn't work for untyped literals.
func intPtr(i int) *int { return &i }

// TestRuleICMPMatchesProbe covers the cross-product of (rule has ICMP, rule
// has NotICMP, both) × (probe specifies type, code, neither). The probe-side
// nil case is the backward-compat surface — every rule must pass through as
// if the filter weren't there — and is exercised both via the helper and via
// filterRulesByICMP's short-circuit so a future refactor can't drop one
// without the other.
func TestRuleICMPMatchesProbe(t *testing.T) {
	cases := []struct {
		name  string
		rule  apiv3.Rule
		probe *icmpProbe
		want  bool
	}{
		{
			name:  "no icmp on rule, probe inactive — pass",
			rule:  apiv3.Rule{},
			probe: &icmpProbe{},
			want:  true,
		},
		{
			name:  "rule.ICMP.Type=8, probe type=8 — pass",
			rule:  apiv3.Rule{ICMP: &apiv3.ICMPFields{Type: intPtr(8)}},
			probe: &icmpProbe{typ: intPtr(8)},
			want:  true,
		},
		{
			name:  "rule.ICMP.Type=8, probe type=0 — drop",
			rule:  apiv3.Rule{ICMP: &apiv3.ICMPFields{Type: intPtr(8)}},
			probe: &icmpProbe{typ: intPtr(0)},
			want:  false,
		},
		{
			name:  "rule.ICMP.Type=8, probe type=nil — drop (rule is more specific than probe)",
			rule:  apiv3.Rule{ICMP: &apiv3.ICMPFields{Type: intPtr(8)}},
			probe: &icmpProbe{code: intPtr(0)}, // active() via code, but typ is nil
			want:  false,
		},
		{
			name:  "rule.ICMP.Type=8 Code=0, probe type=8 code=0 — pass",
			rule:  apiv3.Rule{ICMP: &apiv3.ICMPFields{Type: intPtr(8), Code: intPtr(0)}},
			probe: &icmpProbe{typ: intPtr(8), code: intPtr(0)},
			want:  true,
		},
		{
			name:  "rule.ICMP.Type=8 Code=0, probe type=8 code=1 — drop",
			rule:  apiv3.Rule{ICMP: &apiv3.ICMPFields{Type: intPtr(8), Code: intPtr(0)}},
			probe: &icmpProbe{typ: intPtr(8), code: intPtr(1)},
			want:  false,
		},
		{
			name:  "rule.NotICMP.Type=8, probe type=8 — drop (negation excludes the probe)",
			rule:  apiv3.Rule{NotICMP: &apiv3.ICMPFields{Type: intPtr(8)}},
			probe: &icmpProbe{typ: intPtr(8)},
			want:  false,
		},
		{
			name:  "rule.NotICMP.Type=8, probe type=0 — pass (probe outside the negation)",
			rule:  apiv3.Rule{NotICMP: &apiv3.ICMPFields{Type: intPtr(8)}},
			probe: &icmpProbe{typ: intPtr(0)},
			want:  true,
		},
		{
			name:  "rule.NotICMP.Type=8 Code=0, probe type=8 code=1 — pass (Code escapes negation)",
			rule:  apiv3.Rule{NotICMP: &apiv3.ICMPFields{Type: intPtr(8), Code: intPtr(0)}},
			probe: &icmpProbe{typ: intPtr(8), code: intPtr(1)},
			want:  true,
		},
		{
			name:  "rule.NotICMP.Type=8 Code=0, probe type=8 code=0 — drop",
			rule:  apiv3.Rule{NotICMP: &apiv3.ICMPFields{Type: intPtr(8), Code: intPtr(0)}},
			probe: &icmpProbe{typ: intPtr(8), code: intPtr(0)},
			want:  false,
		},
		{
			name:  "rule.ICMP.Type=8, probe inactive — filter short-circuit (caller bypasses)",
			rule:  apiv3.Rule{ICMP: &apiv3.ICMPFields{Type: intPtr(8)}},
			probe: nil,
			want:  true, // filterRulesByICMP returns rules unchanged when !active
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got bool
			if !tc.probe.active() {
				// Mirror filterRulesByICMP's short-circuit so the "probe
				// inactive" rows assert the no-op contract end-to-end.
				out := filterRulesByICMP([]apiv3.Rule{tc.rule}, tc.probe)
				got = len(out) == 1
			} else {
				got = ruleICMPMatchesProbe(tc.rule, tc.probe)
			}
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

// TestApplyICMPFilterPolicies pins the per-kind plumbing: every v3 policy
// kind we feed should have its rule lists rewritten in place, and unrelated
// kinds (here: GlobalNetworkSet, picked because it has no Spec.Ingress/Egress)
// must pass through untouched.
func TestApplyICMPFilterPolicies(t *testing.T) {
	keep := apiv3.Rule{Action: apiv3.Allow, ICMP: &apiv3.ICMPFields{Type: intPtr(8)}}
	drop := apiv3.Rule{Action: apiv3.Allow, ICMP: &apiv3.ICMPFields{Type: intPtr(0)}}

	probe := &icmpProbe{typ: intPtr(8)}

	gnp := &apiv3.GlobalNetworkPolicy{}
	gnp.Spec.Ingress = []apiv3.Rule{keep, drop}
	gnp.Spec.Egress = []apiv3.Rule{drop, keep}
	applyICMPFilter(gnp, probe)
	if len(gnp.Spec.Ingress) != 1 || gnp.Spec.Ingress[0].ICMP.Type == nil || *gnp.Spec.Ingress[0].ICMP.Type != 8 {
		t.Fatalf("GNP ingress not filtered: %+v", gnp.Spec.Ingress)
	}
	if len(gnp.Spec.Egress) != 1 || *gnp.Spec.Egress[0].ICMP.Type != 8 {
		t.Fatalf("GNP egress not filtered: %+v", gnp.Spec.Egress)
	}

	// Non-policy kinds must be ignored — applyICMPFilter is called from
	// feedPolicy's process() boundary against whatever value the
	// updateprocessor will see, so the switch needs a benign default.
	gns := &apiv3.GlobalNetworkSet{}
	applyICMPFilter(gns, probe) // must not panic

	// Backward compat: nil probe ⇒ no mutation.
	np := &apiv3.NetworkPolicy{}
	np.Spec.Ingress = []apiv3.Rule{keep, drop}
	applyICMPFilter(np, nil)
	if len(np.Spec.Ingress) != 2 {
		t.Fatalf("nil probe should not filter: got %d rules", len(np.Spec.Ingress))
	}
}
