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

// hns.go renders the Windows HNS (Host Networking Service) ACL policies Felix
// would program for each workload endpoint, reusing the same calc graph
// Evaluate/RenderIptables/RenderBPF use (buildGraph) and driving Felix's own
// felix/dataplane/windows/policysets renderer.
//
// This compiles and runs on Linux because Calico ships Linux stubs for the
// hcsshim types (felix/dataplane/windows/hns/hns_linux.go); the renderer never
// touches a real HNS API, it just produces the ACLPolicy structs that would be
// handed to HNS on a Windows node.
//
// Like the BPF render (and UNLIKE iptables/nftables) HNS policy is NOT a global
// chain set: each workload endpoint gets its own ordered list of ACL rules per
// direction (In / Out). So we render one ACL list per (endpoint, direction).
//
// Two faithfulness caveats inherent to Windows:
//
//   - IPv4 ONLY. The upstream policysets package hard-codes ipVersion=4 (IPv6
//     "will be added once dataplane support is available"). So an IPv6 request
//     is reported as unsupported rather than rendered.
//   - We report a "modern" HNS feature set (address lists, port ranges, rule
//     IDs) so the output reflects what current Windows builds program. A real
//     node detects features at runtime; an older node would render the same
//     policy slightly differently (e.g. exploded ports).
//
// As with the other renderers, buildGraph is called with a nil ICMP probe:
// the HNS renderer skips ICMP type/code rules natively (Windows can't express
// them), so no probe-specific pre-filtering is wanted.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bitset"

	"github.com/projectcalico/calico/felix/dataplane/windows/hns"
	"github.com/projectcalico/calico/felix/dataplane/windows/policysets"
	"github.com/projectcalico/calico/felix/iputils"
	"github.com/projectcalico/calico/felix/proto"
	apptypes "github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"

	"github.com/projectcalico/calico/app-policy/policystore"
)

// HNSOptions filters what RenderHNS emits. Zero value renders every endpoint,
// both directions.
type HNSOptions struct {
	// Endpoints, when non-empty, restricts output to endpoints whose ID
	// ("<ns>/<name>") contains any of these substrings.
	Endpoints []string
	// Directions to render: "ingress" and/or "egress". Empty renders both.
	Directions []string
	// IPVersions requested. HNS renders IPv4 only; a request for 6 produces a
	// warning rather than output. Empty defaults to [4].
	IPVersions []int
}

// HNSRule is one rendered HNS ACL policy (rule). Its JSON tags and field order
// reproduce hcsshim's ACLPolicy exactly, so the -json output is the literal
// blob Felix marshals into an HNSEndpoint's Policies[] and hands to HNS — the
// Windows analogue of an `iptables -A` line. The single-port / Protocols /
// ServiceName ACLPolicy fields are omitted: Calico's policysets renderer never
// populates them, so real nodes omit them too (omitempty).
type HNSRule struct {
	Type            string `json:"Type"`
	ID              string `json:"Id,omitempty"`
	Protocol        uint16 `json:"Protocol,omitempty"`
	Action          string `json:"Action"`
	Direction       string `json:"Direction"`
	LocalAddresses  string `json:"LocalAddresses,omitempty"`
	RemoteAddresses string `json:"RemoteAddresses,omitempty"`
	LocalPorts      string `json:"LocalPorts,omitempty"`
	RemotePorts     string `json:"RemotePorts,omitempty"`
	RuleType        string `json:"RuleType,omitempty"`
	Priority        uint16 `json:"Priority,omitempty"`
}

// HNSEndpointPolicy is the rendered ACL list for one (endpoint, direction). It
// is the flattened, priority-rewritten list HNS would receive — i.e. what
// Felix installs, after tier flattening (felix/dataplane/windows/flattener.go).
type HNSEndpointPolicy struct {
	Endpoint  string    `json:"endpoint"`
	Interface string    `json:"interface"`
	Direction string    `json:"direction"`
	IPVersion int       `json:"ipVersion"`
	Rules     []HNSRule `json:"rules"`
	Error     string    `json:"error,omitempty"`
}

// HNSResponse is the rendered ACL lists plus feed-time warnings/errors.
type HNSResponse struct {
	Endpoints []HNSEndpointPolicy `json:"endpoints"`
	Warnings  []string            `json:"warnings,omitempty"`
	Errors    []string            `json:"errors,omitempty"`
}

// RenderHNS builds the calc graph for req and renders the HNS ACL list for each
// selected endpoint × direction.
func RenderHNS(req Request, opts HNSOptions) HNSResponse {
	resp := HNSResponse{}

	req, inlineErrs := applyInlineResources(req)

	g := buildGraph(req, nil)
	resp.Warnings = g.warnings
	resp.Warnings = append(resp.Warnings, lintWindowsHNS(g)...)
	resp.Errors = append(inlineErrs, g.errors...)

	for _, v := range opts.IPVersions {
		if v == 6 {
			resp.Warnings = append(resp.Warnings,
				"HNS renders IPv4 only; IPv6 request ignored (Calico Windows has no IPv6 ACL support yet)")
		}
	}

	directions := opts.Directions
	if len(directions) == 0 {
		directions = []string{"ingress", "egress"}
	}

	// One PolicySets plane, seeded with an IP-set cache backed by the graph's
	// policystore so rules that reference selectors resolve to member addresses
	// (HNS inlines addresses into ACLs rather than referencing named sets).
	ps := policysets.NewPolicySets(
		modernHNSAPI{},
		[]policysets.IPSetCache{graphIPSetCache{g.ipSetMembers}},
		noStaticRules{},
	)

	for _, id := range sortedKeys(g.wepByID) {
		if !matchesAny(id, opts.Endpoints) {
			continue
		}
		wep := g.wepByID[id]
		registerEndpointPolicySets(ps, wep, g.store)

		for _, dir := range directions {
			ingress := dir == "ingress"
			ep := HNSEndpointPolicy{
				Endpoint:  id,
				Interface: wep.GetName(),
				Direction: dir,
				IPVersion: 4,
			}
			rules, err := renderHNSEndpoint(ps, wep, ingress)
			if err != nil {
				ep.Error = err.Error()
			}
			ep.Rules = rules
			resp.Endpoints = append(resp.Endpoints, ep)
		}
	}
	return resp
}

// lintWindowsHNS flags policy rules that Felix's Windows HNS renderer will
// silently drop, changing the verdict versus Linux. It mirrors the exact
// predicates in felix/dataplane/windows/policysets.protoRuleToHnsRules
// (negative matches, ICMP type/code, named ports), plus the HostEndpoint gap:
// RenderHNS renders workload endpoints only, and Windows Calico programs no
// host-endpoint policy at all. See win_limitation.md. RenderHNS is the Windows
// path by construction, so no per-endpoint OS check is needed.
func lintWindowsHNS(g graphResult) []string {
	var warnings []string
	for id, pol := range g.store.PolicyByID {
		for _, r := range append(append([]*proto.Rule{}, pol.GetInboundRules()...), pol.GetOutboundRules()...) {
			if reason := windowsDropReason(r); reason != "" {
				warnings = append(warnings, fmt.Sprintf(
					"%s %s: %s - Windows HNS renderer drops this rule, so its verdict "+
						"diverges from Linux based dataplanes", id.Kind, id.Name, reason))
			}
		}
	}
	// tier-pass-block: an explicit Pass-action RULE in a default-tier policy.
	// The default tier is the terminal tier for a workload endpoint (profiles
	// are only appended when the default tier contributes no policies), so
	// flattenTiers rewrites its trailing Pass to Block — on Linux the matched
	// Pass falls through to the namespace profile (allow), on Windows it denies.
	// A Pass in a non-default tier flattens into the next tier and is faithful.
	seenPass := map[string]bool{}
	for _, wep := range g.wepByID {
		for _, t := range wep.GetTiers() {
			if t.GetName() != "default" {
				continue
			}
			for _, pid := range append(append([]*proto.PolicyID{}, t.GetIngressPolicies()...), t.GetEgressPolicies()...) {
				tid := apptypes.ProtoToPolicyID(pid)
				if model.KindIsStaged(tid.Kind) || seenPass[tid.Name] {
					continue
				}
				if pol := g.store.PolicyByID[tid]; pol != nil && policyHasPassRule(pol) {
					seenPass[tid.Name] = true
					warnings = append(warnings, fmt.Sprintf(
						"%s %s: A full or a partial policy that becomes a pass in Windows"+
							"will drop the traffic if its action is not determined in the same tier",
						tid.Kind, tid.Name))
				}
			}
		}
	}
	if len(g.hepByName) > 0 {
		warnings = append(warnings,
			"HostEndpoint and HEP policies (applyOnForward / doNotTrack / preDNAT) are not supported by "+
				"Windows; these rules have no effect there")
	}
	sort.Strings(warnings)
	return warnings
}

// policyHasPassRule reports whether pol contains an explicit Pass-action rule.
func policyHasPassRule(pol *proto.Policy) bool {
	for _, r := range append(append([]*proto.Rule{}, pol.GetInboundRules()...), pol.GetOutboundRules()...) {
		if strings.EqualFold(r.GetAction(), "pass") || strings.EqualFold(r.GetAction(), "next-tier") {
			return true
		}
	}
	return false
}

// windowsDropReason returns why the Windows HNS renderer would drop r, or "".
func windowsDropReason(r *proto.Rule) string {
	switch {
	case len(r.GetNotSrcNet()) > 0 || len(r.GetNotDstNet()) > 0:
		return "negated CIDR match (notNets)"
	case len(r.GetNotSrcPorts()) > 0 || len(r.GetNotDstPorts()) > 0:
		return "negated port match (notPorts)"
	case len(r.GetNotSrcIpSetIds()) > 0 || len(r.GetNotDstIpSetIds()) > 0:
		return "negated selector match (notSelector)"
	case len(r.GetNotSrcNamedPortIpSetIds()) > 0 || len(r.GetNotDstNamedPortIpSetIds()) > 0:
		return "negated named-port match"
	case r.GetNotProtocol() != nil:
		return "negated protocol match (notProtocol)"
	case r.GetNotIcmp() != nil:
		return "negated ICMP match (notICMP)"
	case r.GetIcmp() != nil:
		return "ICMP type/code match"
	case len(r.GetSrcNamedPortIpSetIds()) > 0 || len(r.GetDstNamedPortIpSetIds()) > 0:
		return "named-port match"
	}
	return ""
}

// registerEndpointPolicySets idempotently loads every policy/profile the
// endpoint references into the PolicySets plane, under the same set-ID strings
// the lookup path (renderHNSEndpoint) uses. Mirrors how the Windows
// policyManager registers ActivePolicyUpdate/ActiveProfileUpdate messages.
func registerEndpointPolicySets(ps *policysets.PolicySets, wep *proto.WorkloadEndpoint, store *policystore.PolicyStore) {
	for _, t := range wep.GetTiers() {
		pols := append(append([]*proto.PolicyID{}, t.GetIngressPolicies()...), t.GetEgressPolicies()...)
		for _, pid := range pols {
			tid := apptypes.ProtoToPolicyID(pid)
			if model.KindIsStaged(tid.Kind) {
				continue
			}
			if pol := store.PolicyByID[tid]; pol != nil {
				ps.AddOrReplacePolicySet(hnsPolicyIDToString(policysets.PolicyNamePrefix, pid), pol)
			}
		}
	}
	for _, pn := range wep.GetProfileIds() {
		if prof := store.ProfileByID[apptypes.ProfileID{Name: pn}]; prof != nil {
			ps.AddOrReplacePolicySet(policysets.ProfileNamePrefix+pn, prof)
		}
	}
}

// renderHNSEndpoint reproduces the Windows endpointManager's per-endpoint rule
// assembly for one direction: gather each applicable tier's ACL rules, fall
// through to the profiles when the default tier has no policies, then flatten
// the tiers and rewrite priorities into the final ascending list HNS receives.
// The policysets renderer panics on a few unexpected inputs (e.g. unknown rule
// action), so we recover and report per endpoint rather than crashing the run.
func renderHNSEndpoint(ps *policysets.PolicySets, wep *proto.WorkloadEndpoint, ingress bool) (out []HNSRule, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("policysets panic: %v", r)
		}
	}()

	var tierRules [][]*hns.ACLPolicy
	defaultTierApplies := false
	for _, t := range wep.GetTiers() {
		endOfTierDrop := t.GetDefaultAction() != "Pass"
		pols := t.GetEgressPolicies()
		if ingress {
			pols = t.GetIngressPolicies()
		}
		if len(pols) == 0 {
			continue
		}
		if t.GetName() == "default" {
			defaultTierApplies = true
		}
		tierRules = append(tierRules, ps.GetPolicySetRules(
			hnsPolicyIDsToStrings(policysets.PolicyNamePrefix, pols), ingress, endOfTierDrop))
	}

	// If no policies apply (or the default tier contributes none) we fall
	// through to the profiles — there's no other way to reach them.
	if len(tierRules) == 0 || !defaultTierApplies {
		profNames := make([]string, 0, len(wep.GetProfileIds()))
		for _, pn := range wep.GetProfileIds() {
			profNames = append(profNames, policysets.ProfileNamePrefix+pn)
		}
		tierRules = append(tierRules, ps.GetPolicySetRules(profNames, ingress, true))
	}

	flat := flattenTiers(tierRules)
	rewritePriorities(flat, policysets.PolicyRuleMaxPriority)

	out = make([]HNSRule, 0, len(flat))
	for _, r := range flat {
		out = append(out, HNSRule{
			Type:            string(r.Type),
			ID:              r.Id,
			Action:          string(r.Action),
			Direction:       string(r.Direction),
			RuleType:        string(r.RuleType),
			Protocol:        r.Protocol,
			LocalAddresses:  r.LocalAddresses,
			RemoteAddresses: r.RemoteAddresses,
			LocalPorts:      r.LocalPorts,
			RemotePorts:     r.RemotePorts,
			Priority:        r.Priority,
		})
	}
	return out, nil
}

// graphIPSetCache serves IP-set members captured from the calc graph's
// IPSetUpdate payloads (buildGraph stashes them; the policystore's NET-set
// trie can't enumerate them). HNS ACLs inline member addresses, so the renderer
// asks for each referenced set's members. A nil return means "not in this
// cache" (the renderer then treats the set as missing and skips the rule); a
// present-but-empty set returns a non-nil empty slice so it isn't mistaken for
// a missing one.
type graphIPSetCache struct{ members map[string][]string }

func (c graphIPSetCache) GetIPSetMembers(id string) []string {
	if m, ok := c.members[id]; ok {
		if m == nil {
			return []string{}
		}
		return m
	}
	return nil
}

// modernHNSAPI reports a current-generation HNS feature set so the render uses
// the richer encodings (address lists, port ranges, per-rule IDs). The Linux
// stub (hns.API) reports no features, which would yield an older, more verbose
// rendering; we override it to reflect what current Windows nodes program.
type modernHNSAPI struct{}

func (modernHNSAPI) GetHNSSupportedFeatures() hns.HNSSupportedFeatures {
	return hns.HNSSupportedFeatures{Acl: hns.HNSAclFeatures{
		AclAddressLists:       true,
		AclNoHostRulePriority: true,
		AclPortRanges:         true,
		AclRuleId:             true,
	}}
}

// noStaticRules is a StaticRulesReader that reports no static rules file (the
// Windows node ships one alongside calico-node.exe; there's no equivalent for
// a static render).
type noStaticRules struct{}

func (noStaticRules) ReadData() ([]byte, error) { return nil, policysets.ErrNoRuleSpecified }

// hnsPolicyIDToString / hnsPolicyIDsToStrings / and the flattener helpers below
// are ported from felix/dataplane/windows (endpoint_mgr.go, flattener.go) so
// the rendered ACL list matches what the Windows dataplane installs. They live
// in the unexported windataplane package upstream, hence the copy.

func hnsPolicyIDToString(prefix string, id *proto.PolicyID) string {
	if id.GetNamespace() != "" {
		return fmt.Sprintf("%s%s/%s/%s", prefix, id.GetKind(), id.GetNamespace(), id.GetName())
	}
	return fmt.Sprintf("%s%s/%s", prefix, id.GetKind(), id.GetName())
}

func hnsPolicyIDsToStrings(prefix string, in []*proto.PolicyID) []string {
	out := make([]string, 0, len(in))
	for _, id := range in {
		out = append(out, hnsPolicyIDToString(prefix, id))
	}
	return out
}

// flattenTiers coalesces a per-tier list of ACL rules into a single list,
// resolving cross-tier "pass" actions. The last tier can't pass anywhere, so
// any pass there becomes a block first.
func flattenTiers(tiers [][]*hns.ACLPolicy) []*hns.ACLPolicy {
	if len(tiers) == 0 {
		return nil
	}
	lastTier := tiers[len(tiers)-1]
	for _, r := range lastTier {
		if r.Action == policysets.ActionPass {
			r.Action = hns.Block
		}
	}
	return flattenTiersRecurse(tiers)
}

func flattenTiersRecurse(tiers [][]*hns.ACLPolicy) []*hns.ACLPolicy {
	if len(tiers) == 0 {
		return nil
	}
	if len(tiers) == 1 {
		return tiers[0]
	}

	foundPass := false
	oldFirstTier := tiers[0]
	var newFirstTier []*hns.ACLPolicy
	for _, r := range oldFirstTier {
		if r.Action == policysets.ActionPass {
			foundPass = true
			newFirstTier = appendCombinedRules(newFirstTier, tiers[1], r)
		} else {
			newFirstTier = append(newFirstTier, r)
		}
	}

	if !foundPass {
		// Further tiers exist but nothing passes into them, so they're unreachable.
		return oldFirstTier
	}

	tiers = tiers[1:]
	tiers[0] = newFirstTier
	return flattenTiersRecurse(tiers)
}

func appendCombinedRules(newRules []*hns.ACLPolicy, secondTier []*hns.ACLPolicy, rule *hns.ACLPolicy) []*hns.ACLPolicy {
	for _, r := range secondTier {
		combinedRule := combineRules(rule, r)
		if combinedRule == nil {
			continue // would be a no-op
		}
		newRules = append(newRules, combinedRule)
	}
	return newRules
}

// combineRules calculates r1 && r2, using the action/ID from r2.
func combineRules(r1, r2 *hns.ACLPolicy) *hns.ACLPolicy {
	combined := *r2

	if r1.Protocol != 256 {
		if r2.Protocol == 256 {
			combined.Protocol = r1.Protocol
		} else if r1.Protocol != r2.Protocol {
			return nil
		}
	}
	var err error
	if combined.LocalAddresses, err = combineCIDRs(r1.LocalAddresses, r2.LocalAddresses); err == policysets.ErrRuleIsNoOp {
		return nil
	}
	if combined.RemoteAddresses, err = combineCIDRs(r1.RemoteAddresses, r2.RemoteAddresses); err == policysets.ErrRuleIsNoOp {
		return nil
	}
	if combined.LocalPorts, err = combinePorts(r1.LocalPorts, r2.LocalPorts); err == policysets.ErrRuleIsNoOp {
		return nil
	}
	if combined.RemotePorts, err = combinePorts(r1.RemotePorts, r2.RemotePorts); err == policysets.ErrRuleIsNoOp {
		return nil
	}
	return &combined
}

func combinePorts(as, bs string) (string, error) {
	if len(as) == 0 {
		return bs, nil
	}
	if len(bs) == 0 {
		return as, nil
	}

	aBitset := parsePorts(as)
	aBitset.InPlaceIntersection(parsePorts(bs))
	if aBitset.Len() == 0 {
		return "", policysets.ErrRuleIsNoOp
	}

	i := uint(0)
	var outPorts []string
	for {
		startOfRange, valid := aBitset.NextSet(i)
		if !valid {
			break
		}
		afterEndOfRange, valid := aBitset.NextClear(startOfRange + 1)
		if !valid {
			break
		}
		endOfRange := afterEndOfRange - 1
		if startOfRange == endOfRange {
			outPorts = append(outPorts, fmt.Sprint(startOfRange))
		} else {
			outPorts = append(outPorts, fmt.Sprintf("%d-%d", startOfRange, endOfRange))
		}
		i = afterEndOfRange + 1
	}
	return strings.Join(outPorts, ","), nil
}

func parsePorts(portsStr string) *bitset.BitSet {
	setOfPorts := bitset.New(1 << 16)
	for _, p := range strings.Split(portsStr, ",") {
		if strings.Contains(p, "-") {
			parts := strings.Split(p, "-")
			low, err := strconv.Atoi(parts[0])
			if err != nil {
				continue
			}
			high, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			for port := low; port <= high; port++ {
				setOfPorts.Set(uint(port))
			}
		} else if port, err := strconv.Atoi(p); err == nil {
			setOfPorts.Set(uint(port))
		}
	}
	return setOfPorts
}

func combineCIDRs(as, bs string) (string, error) {
	if len(as) == 0 {
		return bs, nil
	}
	if len(bs) == 0 {
		return as, nil
	}
	combined := strings.Join(
		iputils.IntersectCIDRs(strings.Split(as, ","), strings.Split(bs, ",")), ",")
	if combined == "" {
		return "", policysets.ErrRuleIsNoOp
	}
	return combined, nil
}

// rewritePriorities renumbers the flattened rules so HNS, which has a different
// tie-break to Calico, preserves Calico's first-match-wins ordering. Ascending
// priorities; rules are grouped by action only if the count would exceed the
// available priority space.
func rewritePriorities(policies []*hns.ACLPolicy, limit uint16) {
	if len(policies) <= 1 {
		return
	}

	currentPriority := policysets.PolicyRuleBasePriority
	policies[0].Priority = currentPriority
	lastRule := policies[0]

	alwaysIncrementPriority := len(policies) < int(limit-currentPriority)
	if alwaysIncrementPriority {
		for i := 1; i < len(policies); i++ {
			currentPriority++
			policies[i].Priority = currentPriority
		}
		return
	}
	for i := 1; i < len(policies); i++ {
		if lastRule.Action != policies[i].Action {
			currentPriority++
		}
		policies[i].Priority = currentPriority
		lastRule = policies[i]
	}
}
