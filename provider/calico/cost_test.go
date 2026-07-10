// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Telepathy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License").

package calico

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frozenprocess/telepathy/api"
)

// TestCostDataplane pins the Calico dataplane weight to the renderers it
// summarises: the iptables weight must equal the "-A" lines RenderIptables
// emits, and the bpf weight must equal the instruction count RenderBPF reports.
// If either render's shape changes, this fails instead of drifting silently.
func TestCostDataplane(t *testing.T) {
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

	// Peer breadth is dataplane-independent: the IP-set membership the calc
	// graph resolves. Every dataplane weight must report this same number.
	preReq, _ := applyInlineResources(req)
	g := buildGraph(preReq, nil)
	wantPeers := 0
	for _, members := range g.ipSetMembers {
		wantPeers += len(members)
	}
	if wantPeers == 0 {
		t.Fatal("expected a non-zero peer-entry count for this case")
	}

	countLines := func(backend string, isRule func(string) bool) int {
		n := 0
		for _, dp := range RenderIptables(req, IptablesOptions{Backends: []string{backend}, IncludeStatic: false}).Dataplanes {
			for _, tbl := range dp.Tables {
				for _, c := range tbl.Chains {
					for _, line := range c.Lines {
						if isRule(line) {
							n++
						}
					}
				}
			}
		}
		return n
	}

	// bpf instruction count from the renderer.
	wantInsns := 0
	for _, p := range RenderBPF(req, BPFOptions{}).Programs {
		wantInsns += p.Instructions
	}
	// hns ACL count from the renderer.
	wantACLs := 0
	for _, ep := range RenderHNS(req, HNSOptions{}).Endpoints {
		wantACLs += len(ep.Rules)
	}

	cases := []struct {
		dataplane, kind, unit string
		wantRules             int
	}{
		{"iptables", "iptables", "rules", countLines("iptables", func(l string) bool { return strings.HasPrefix(l, "-A ") })},
		{"nftables", "nftables", "rules", countLines("nftables", func(l string) bool { return strings.HasPrefix(l, "  ") })},
		{"bpf", "ebpf", "instructions", wantInsns},
		{"hns", "hns", "acl-rules", wantACLs},
	}
	for _, tc := range cases {
		if tc.wantRules == 0 {
			t.Errorf("%s: expected a non-zero rule count", tc.dataplane)
		}
		req.CostDataplane = tc.dataplane
		w := costDataplane(req)
		if w.Kind != tc.kind || w.RulesUnit != tc.unit || w.Rules != tc.wantRules {
			t.Errorf("%s weight = %+v, want kind=%s rulesUnit=%s rules=%d", tc.dataplane, w, tc.kind, tc.unit, tc.wantRules)
		}
		if w.PeerEntries != wantPeers {
			t.Errorf("%s peerEntries = %d, want %d (dataplane-independent)", tc.dataplane, w.PeerEntries, wantPeers)
		}
		if w.IPSets != len(g.ipSetMembers) {
			t.Errorf("%s ipSets = %d, want %d", tc.dataplane, w.IPSets, len(g.ipSetMembers))
		}
	}

	// #2: MaxStack is filled by Evaluate from the calc graph and must equal the
	// busiest endpoint's distinct-policy count.
	req.Cost = true
	req.CostDataplane = ""
	full := Evaluate(req)
	if full.Cost == nil {
		t.Fatal("Evaluate did not fill Cost")
	}
	if got, want := full.Cost.Structural.MaxStack, maxPoliciesPerEndpoint(g.wepByID); got != want {
		t.Errorf("MaxStack = %d, want %d", got, want)
	}
	if full.Cost.Structural.MaxStack == 0 {
		t.Fatal("expected a non-zero MaxStack for this case")
	}
	if full.Cost.Structural.ResolvedPeers != wantPeers {
		t.Errorf("ResolvedPeers = %d, want %d", full.Cost.Structural.ResolvedPeers, wantPeers)
	}
}
