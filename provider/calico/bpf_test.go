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
	"os"
	"path/filepath"
	"testing"

	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/proto"

	"github.com/frozenprocess/telepathy/api"
)

// TestBpfTreeProjection exercises bpfTree/bpfRule directly: protocol naming,
// IP-set-to-member resolution, port ranges, ICMP, profiles, and per-IP-version
// filtering — without going through the compiler at all.
func TestBpfTreeProjection(t *testing.T) {
	members := map[string][]string{"s:web": {"10.1.0.1/32", "10.1.0.2/32"}}
	icmpCode := int32(0)

	rls := polprog.Rules{
		Tiers: []polprog.Tier{{
			Name:      "default",
			EndAction: polprog.TierEndPass,
			Policies: []polprog.Policy{{
				Kind: "GlobalNetworkPolicy", Name: "allow-web",
				Rules: []polprog.Rule{
					{MatchID: 111, Rule: &proto.Rule{
						Action:      "Allow",
						Protocol:    &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
						SrcIpSetIds: []string{"s:web"},
						DstPorts:    []*proto.PortRange{{First: 443, Last: 443}},
					}},
					{MatchID: 222, Rule: &proto.Rule{
						Action: "Deny",
						Icmp:   &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: 8, Code: icmpCode}},
					}},
					{MatchID: 333, Rule: &proto.Rule{
						// IPv6-only: dropped entirely when rendering an IPv4 program.
						IpVersion: 6,
						SrcNet:    []string{"fd00::/64"},
					}},
				},
			}},
		}},
		Profiles: []polprog.Profile{{Name: "kns.default", Rules: []polprog.Rule{
			{MatchID: 444, Rule: &proto.Rule{}}, // bare rule: empty action defaults to allow
		}}},
	}

	tiers, profiles := bpfTree(rls, members, 4)

	if len(tiers) != 1 || tiers[0].Name != "default" || tiers[0].DefaultAction != "pass" {
		t.Fatalf("tier shape: %+v", tiers)
	}
	rs := tiers[0].Policies[0].Rules
	if len(rs) != 3 {
		t.Fatalf("want 3 rules, got %d: %+v", len(rs), rs)
	}

	allow := rs[0]
	if allow.Action != "allow" || allow.Protocol != "tcp" || allow.MatchID != 111 {
		t.Errorf("rule0: %+v", allow)
	}
	if allow.Source == nil || len(allow.Source.IPSets) != 1 || allow.Source.IPSets[0].ID != "s:web" ||
		len(allow.Source.IPSets[0].Members) != 2 {
		t.Errorf("rule0 source IP set not resolved to members: %+v", allow.Source)
	}
	if allow.Destination == nil || len(allow.Destination.Ports) != 1 || allow.Destination.Ports[0].First != 443 {
		t.Errorf("rule0 destination ports: %+v", allow.Destination)
	}

	icmpRule := rs[1]
	if icmpRule.Action != "deny" || icmpRule.ICMP == nil || icmpRule.ICMP.Type != 8 || icmpRule.ICMP.Code == nil || *icmpRule.ICMP.Code != 0 {
		t.Errorf("rule1 icmp: %+v", icmpRule.ICMP)
	}

	v6Only := rs[2]
	if v6Only.Source != nil || v6Only.Destination != nil {
		t.Errorf("rule2 should carry no match in an IPv4 program: %+v", v6Only)
	}

	if len(profiles) != 1 || profiles[0].Name != "kns.default" || len(profiles[0].Rules) != 1 {
		t.Fatalf("profiles: %+v", profiles)
	}
	if profiles[0].Rules[0].Action != "allow" {
		t.Errorf("bare rule should default to allow, got %q", profiles[0].Rules[0].Action)
	}
}

// TestRenderBPFInstructionsBothModes pins RenderBPF's Instructions/SubPrograms
// bookkeeping: cost.go's bpfWeight sums Instructions off the DEFAULT (concise)
// render, so it must be populated even though concise no longer needs the
// compiled program for anything else. Verbose must report the identical count
// for the same input — it's the same compile, just two different views of it.
func TestRenderBPFInstructionsBothModes(t *testing.T) {
	dir := filepath.Join("..", "..", "e2e", "testdata", "calico-default-deny-allow-database-only")
	topo, err := os.ReadFile(filepath.Join(dir, "topology.yaml"))
	if err != nil {
		t.Fatalf("read topology: %v", err)
	}
	req, err := api.DecodeRequest(topo)
	if err != nil {
		t.Fatalf("decode topology: %v", err)
	}
	pol, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	req.Policies = append(req.Policies, api.ParsePolicyManifests(pol)...)

	concise := RenderBPF(req, BPFOptions{})
	verbose := RenderBPF(req, BPFOptions{Verbose: true})
	if len(concise.Programs) == 0 || len(concise.Programs) != len(verbose.Programs) {
		t.Fatalf("expected matching non-empty program sets, got concise=%d verbose=%d",
			len(concise.Programs), len(verbose.Programs))
	}

	sawTieredProgram := false
	for i := range concise.Programs {
		c, v := concise.Programs[i], verbose.Programs[i]
		if c.Error != "" || v.Error != "" {
			t.Fatalf("program %d: concise err=%q verbose err=%q", i, c.Error, v.Error)
		}
		if c.Instructions == 0 || c.Instructions != v.Instructions {
			t.Errorf("program %d instructions mismatch: concise=%d verbose=%d", i, c.Instructions, v.Instructions)
		}
		if len(c.Lines) != 0 {
			t.Errorf("program %d: concise render should not populate Lines, got %d", i, len(c.Lines))
		}
		if len(v.Tiers) != 0 || len(v.Profiles) != 0 {
			t.Errorf("program %d: verbose render should not populate Tiers/Profiles", i)
		}
		if len(v.Lines) == 0 {
			t.Errorf("program %d: verbose render should populate Lines", i)
		}
		if len(c.Tiers) > 0 || len(c.Profiles) > 0 {
			sawTieredProgram = true
		}
	}
	if !sawTieredProgram {
		t.Fatal("expected at least one program with a non-empty concise Tiers/Profiles tree")
	}
}
