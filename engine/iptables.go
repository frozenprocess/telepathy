// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 The Telepathy Authors
//
// This file is part of Telepathy.
//
// Telepathy is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License version 3 as published
// by the Free Software Foundation.
//
// Telepathy is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.

package engine

// iptables.go renders the dataplane chains Felix would program for a Request,
// reusing the same calc graph Evaluate uses (buildGraph) and then driving
// Felix's own felix/rules renderer + felix/iptables|felix/nftables command
// renderers. The result is the actual iptables-restore input (or nftables
// rule bodies) for the *filter* table — where Calico policy lives.
//
// This is a DIFFERENT code path from Evaluate's verdict: the matrix comes from
// the app-policy checker, this comes from the dataplane renderer. They agree
// for supported features, but the rendered rules are "what Felix installs",
// not "what the checker computed". Notably the renderer handles named ports /
// ICMP type+code natively (no probe-specific filtering — buildGraph is called
// with a nil ICMP probe here), so the rendered chains can be richer than the
// checker-driven matrix for those features.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

// IptablesOptions controls what RenderIptables emits. Zero value is a sensible
// default: iptables backend, IP version(s) inferred from the endpoints, and
// the static top-level chains (cali-INPUT/FORWARD/OUTPUT) included.
type IptablesOptions struct {
	// Backends is the set of dataplane renderers to produce. Valid entries:
	// "iptables", "nftables". Empty defaults to ["iptables"].
	Backends []string
	// IPVersions to render (4 and/or 6). Empty infers from endpoint IPs,
	// falling back to [4].
	IPVersions []int
	// IncludeStatic includes Felix's static top-level filter chains (the
	// cali-INPUT/FORWARD/OUTPUT entry points + their dispatch helpers). These
	// are policy-independent boilerplate; set false to show only the chains
	// that are a function of the Request's policies/endpoints/profiles.
	IncludeStatic bool
	// Endpoints, when non-empty, restricts output to the chains involved in
	// enforcing the matched endpoints: their per-endpoint + dispatch chains,
	// plus only the per-policy / per-profile chains those endpoints reference.
	// An endpoint matches if its ID ("<ns>/<name>") contains any of these
	// substrings (mirrors BPFOptions.Endpoints). Empty renders every chain.
	Endpoints []string
}

// RenderedChain is one dataplane chain rendered to command lines. For iptables
// the first line is the `:chain - [0:0]` declaration followed by `-A` append
// lines; for nftables it's a `chain NAME {` block of rule bodies.
type RenderedChain struct {
	Name  string   `json:"name"`
	Lines []string `json:"lines"`
}

// RenderedTable groups chains by iptables/nftables table. Only "filter" is
// emitted today (where policy lives).
type RenderedTable struct {
	Table  string          `json:"table"`
	Chains []RenderedChain `json:"chains"`
}

// RenderedDataplane is the full chain set for one (backend, ipVersion) combo.
type RenderedDataplane struct {
	Backend   string          `json:"backend"`
	IPVersion int             `json:"ipVersion"`
	Tables    []RenderedTable `json:"tables"`
}

// IptablesResponse is the rendered output plus any feed-time warnings/errors
// (same sources as engine.Response).
type IptablesResponse struct {
	Dataplanes []RenderedDataplane `json:"dataplanes"`
	Warnings   []string            `json:"warnings,omitempty"`
	Errors     []string            `json:"errors,omitempty"`
}

// RenderIptables builds the calc graph for req and renders the filter-table
// chains Felix would program, for each requested backend and IP version.
func RenderIptables(req Request, opts IptablesOptions) IptablesResponse {
	resp := IptablesResponse{}

	req, inlineErrs := applyInlineResources(req)

	// nil ICMP probe: render the policies verbatim. The probe-time ICMP
	// filtering (icmp.go) is a workaround for the checker's protocol-only
	// matching; the dataplane renderer encodes icmp type/code directly.
	g := buildGraph(req, nil)
	resp.Warnings = g.warnings
	resp.Errors = append(inlineErrs, g.errors...)

	backends := opts.Backends
	if len(backends) == 0 {
		backends = []string{"iptables"}
	}
	ipVersions := opts.IPVersions
	if len(ipVersions) == 0 {
		ipVersions = ipVersionsForReq(req)
	}

	cfg := renderConfig()
	for _, backend := range backends {
		nft := backend == "nftables"
		rr := rules.NewRenderer(cfg, nft)
		for _, ipv := range ipVersions {
			chains := collectFilterChains(rr, g, cfg, uint8(ipv), opts.IncludeStatic, opts.Endpoints)
			resp.Dataplanes = append(resp.Dataplanes, RenderedDataplane{
				Backend:   backend,
				IPVersion: ipv,
				Tables:    []RenderedTable{{Table: "filter", Chains: renderChains(chains, nft, uint8(ipv))}},
			})
		}
	}
	return resp
}

// renderConfig is a minimal-but-valid felix/rules Config. The mark bits mirror
// Felix's test fixtures (non-zero, non-overlapping so Config.validate passes);
// their exact values are cosmetic for a static render. IPSet prefix "cali"
// matches what the calc graph names its IP sets.
func renderConfig() rules.Config {
	return rules.Config{
		WorkloadIfacePrefixes: []string{"cali"},
		IPSetConfigV4:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
		IPSetConfigV6:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
		MarkAccept:            0x10,
		MarkPass:              0x20,
		MarkScratch0:          0x40,
		MarkScratch1:          0x80,
		MarkDrop:              0x200,
		MarkEndpoint:          0xff000,
		MarkNonCaliEndpoint:   0x1000,
		FilterDenyAction:      "DROP",
	}
}

// collectFilterChains assembles the filter-table chains in dependency order:
// static top-level entry points (optional) → workload dispatch → per-endpoint
// chains → per-policy chains → per-profile chains. Duplicate chain names
// (a chain referenced from several places) are emitted once.
func collectFilterChains(rr rules.RuleRenderer, g graphResult, cfg rules.Config, ipv uint8, includeStatic bool, endpoints []string) []*generictables.Chain {
	var out []*generictables.Chain
	seen := map[string]bool{}
	add := func(cs ...*generictables.Chain) {
		for _, c := range cs {
			if c == nil || seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			out = append(out, c)
		}
	}

	// The matched endpoints drive what's emitted. With no filter every endpoint
	// matches, and policy/profile chains fall back to the whole store (so an
	// orphan policy that selects no endpoint is still shown). With a filter we
	// emit only the chains the matched endpoints actually reference.
	filtering := len(endpoints) > 0
	matchedIDs := make([]string, 0, len(g.wepByID))
	for _, id := range sortedKeys(g.wepByID) {
		if matchesAny(id, endpoints) {
			matchedIDs = append(matchedIDs, id)
		}
	}
	// Policy / profile IDs referenced by the matched endpoints (used only when
	// filtering); a chain is kept if it's in these sets.
	refPolicies := map[string]bool{}
	refProfiles := map[string]bool{}
	for _, id := range matchedIDs {
		w := g.wepByID[id]
		for _, t := range w.GetTiers() {
			for _, n := range append(append([]*proto.PolicyID{}, t.GetIngressPolicies()...), t.GetEgressPolicies()...) {
				refPolicies[policyIDKey(types.ProtoToPolicyID(n))] = true
			}
		}
		for _, pn := range w.GetProfileIds() {
			refProfiles[pn] = true
		}
	}

	if includeStatic {
		add(rr.StaticFilterTableChains(ipv)...)
	}

	// Workload dispatch chains (cali-from-wl-dispatch / cali-to-wl-dispatch),
	// built from the matched endpoints only.
	wepMap := map[types.WorkloadEndpointID]*proto.WorkloadEndpoint{}
	for _, id := range matchedIDs {
		wepMap[types.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: id, EndpointId: "eth0"}] = g.wepByID[id]
	}
	add(rr.WorkloadDispatchChains(wepMap)...)

	// Per-endpoint chains (cali-tw-<iface> / cali-fw-<iface>), which jump into
	// the per-tier policy chains. Sorted by workload ID for stable output.
	emm := rules.NewEndpointMarkMapper(cfg.MarkEndpoint, cfg.MarkNonCaliEndpoint)
	for _, id := range matchedIDs {
		w := g.wepByID[id]
		add(rr.WorkloadEndpointToIptablesChains(
			w.GetName(),
			emm,
			true, // adminUp
			protoTiersToGroups(w.GetTiers()),
			w.GetProfileIds(),
			w.GetQosControls(),
		)...)
	}

	// Per-policy chains (cali-pi-<tier>.<name> / cali-po-...).
	polIDs := make([]types.PolicyID, 0, len(g.store.PolicyByID))
	for id := range g.store.PolicyByID {
		polIDs = append(polIDs, id)
	}
	sort.Slice(polIDs, func(i, j int) bool { return policyIDKey(polIDs[i]) < policyIDKey(polIDs[j]) })
	for _, id := range polIDs {
		if filtering && !refPolicies[policyIDKey(id)] {
			continue
		}
		pid := id
		add(rr.PolicyToIptablesChains(&pid, g.store.PolicyByID[id], ipv)...)
	}

	// Per-profile chains (cali-pri-<name> / cali-pro-<name>).
	profIDs := make([]types.ProfileID, 0, len(g.store.ProfileByID))
	for id := range g.store.ProfileByID {
		profIDs = append(profIDs, id)
	}
	sort.Slice(profIDs, func(i, j int) bool { return profIDs[i].Name < profIDs[j].Name })
	for _, id := range profIDs {
		if filtering && !refProfiles[id.Name] {
			continue
		}
		pid := id
		in, eg := rr.ProfileToIptablesChains(&pid, g.store.ProfileByID[id], ipv)
		add(in, eg)
	}

	return out
}

// protoTiersToGroups converts a proto.WorkloadEndpoint's resolved tier/policy
// ordering into the rules.TierPolicyGroups the endpoint renderer wants. Each
// policy becomes its own single-policy group, so the endpoint chain jumps
// directly to that policy's chain (Felix's real dataplane additionally merges
// policies that share a selector into a group chain; single-policy groups are
// a faithful simplification that keeps the jump targets readable). Mirrors the
// felix/rules test helper tiersToSinglePolGroups.
func protoTiersToGroups(tiers []*proto.TierInfo) []rules.TierPolicyGroups {
	var tgs []rules.TierPolicyGroups
	for _, t := range tiers {
		tg := rules.TierPolicyGroups{Name: t.GetName(), DefaultAction: t.GetDefaultAction()}
		for _, n := range t.GetIngressPolicies() {
			conv := types.ProtoToPolicyID(n)
			tg.IngressPolicies = append(tg.IngressPolicies, &rules.PolicyGroup{Policies: []*types.PolicyID{&conv}})
		}
		for _, n := range t.GetEgressPolicies() {
			conv := types.ProtoToPolicyID(n)
			tg.EgressPolicies = append(tg.EgressPolicies, &rules.PolicyGroup{Policies: []*types.PolicyID{&conv}})
		}
		tgs = append(tgs, tg)
	}
	return tgs
}

// renderChains turns generictables.Chains into command lines for one backend.
func renderChains(chains []*generictables.Chain, nft bool, ipv uint8) []RenderedChain {
	feat := &environment.Features{} // zero value: no kernel-specific optimisations
	out := make([]RenderedChain, 0, len(chains))
	if nft {
		nr := nftables.NewNFTRenderer("cali:", ipv)
		for _, c := range chains {
			rc := RenderedChain{Name: c.Name, Lines: []string{fmt.Sprintf("chain %s {", c.Name)}}
			hashes := nr.RuleHashes(c, feat)
			for i := range c.Rules {
				kr := nr.Render(c.Name, hashes[i], c.Rules[i], feat)
				rc.Lines = append(rc.Lines, "  "+kr.Rule)
			}
			rc.Lines = append(rc.Lines, "}")
			out = append(out, rc)
		}
		return out
	}
	ir := iptables.NewIptablesRenderer("cali:")
	for _, c := range chains {
		rc := RenderedChain{Name: c.Name, Lines: []string{fmt.Sprintf(":%s - [0:0]", c.Name)}}
		hashes := ir.RuleHashes(c, feat)
		for i := range c.Rules {
			rc.Lines = append(rc.Lines, ir.RenderAppend(&c.Rules[i], c.Name, hashes[i], feat))
		}
		out = append(out, rc)
	}
	return out
}

// ipVersionsForReq returns [4], [6], or [4,6] based on the endpoint IP
// families present in the request. Defaults to [4] when none are parseable.
func ipVersionsForReq(req Request) []int {
	v4, v6 := false, false
	for _, ep := range req.Endpoints {
		if strings.Contains(ep.IP, ":") {
			v6 = true
		} else if ep.IP != "" {
			v4 = true
		}
	}
	var out []int
	if v4 {
		out = append(out, 4)
	}
	if v6 {
		out = append(out, 6)
	}
	if len(out) == 0 {
		out = []int{4}
	}
	return out
}

func sortedKeys(m map[string]*proto.WorkloadEndpoint) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func policyIDKey(id types.PolicyID) string { return id.Namespace + "/" + id.Name }
