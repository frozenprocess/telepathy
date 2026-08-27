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

// bpf.go renders the eBPF *policy program* Felix would JIT-assemble for each
// endpoint, reusing the same calc graph Evaluate/RenderIptables use
// (buildGraph) and driving Felix's own felix/bpf/polprog compiler.
//
// Unlike the iptables/nftables render, eBPF policy is NOT a global chain set:
// each workload interface gets its own policy program per direction (tc
// ingress / egress) and per IP family. So we render one program per
// (endpoint, direction, ipVersion).
//
// IMPORTANT framing: polprog only generates the POLICY portion. The rest of
// the BPF dataplane (tc entrypoints, conntrack, NAT, tail-call plumbing) is
// precompiled C object code shipped in the binary, not generated at runtime —
// there is no equivalent of StaticFilterTableChains to emit. The output here
// is therefore "the policy program", annotated with the rule/tier/policy each
// instruction came from (the same artifact `calico-node bpf policy dump
// --asm` prints), not the whole dataplane.
//
// Like the iptables path, buildGraph is called with a nil ICMP probe: polprog
// encodes icmp type/code (and named ports, CIDRs, IP sets) natively from
// proto.Rule, so no probe-specific pre-filtering is wanted.

import (
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Arbitrary program-array jump targets for the final allow/deny verdicts. In a
// live dataplane these index real tail-call slots; for a static render they're
// just the constants that appear in the program's final jump instructions.
const (
	bpfAllowJumpIdx = 1
	bpfDenyJumpIdx  = 2
)

// BPFOptions filters what RenderBPF emits. Zero value renders every endpoint,
// both directions, IP version(s) inferred from the endpoints.
type BPFOptions struct {
	// Endpoints, when non-empty, restricts output to endpoints whose ID
	// ("<ns>/<name>") contains any of these substrings.
	Endpoints []string
	// Directions to render: "ingress" and/or "egress". Empty renders both.
	Directions []string
	// IPVersions to render (4 and/or 6). Empty infers from endpoint IPs.
	IPVersions []int
	// Verbose, when true, emits the full annotated eBPF disassembly
	Verbose bool
}

// BPFProgram changes in new version
type BPFProgram struct {
	Endpoint     string       `json:"endpoint"`
	Interface    string       `json:"interface"`
	Direction    string       `json:"direction"`
	IPVersion    int          `json:"ipVersion"`
	SubPrograms  int          `json:"subPrograms,omitempty"`
	Instructions int          `json:"instructions,omitempty"`
	Tiers        []BPFTier    `json:"tiers,omitempty"`
	Profiles     []BPFProfile `json:"profiles,omitempty"`
	Lines        []string     `json:"lines,omitempty"`
	Error        string       `json:"error,omitempty"`
}

// BPFTier is one policy tier
type BPFTier struct {
	Name          string      `json:"name"`
	DefaultAction string      `json:"defaultAction,omitempty"`
	Policies      []BPFPolicy `json:"policies,omitempty"`
}

// BPFPolicy is one policy within a tier (Kind distinguishes GlobalNetworkPolicy
// / NetworkPolicy / etc.; Namespace is empty for cluster-scoped kinds).
type BPFPolicy struct {
	Kind      string    `json:"kind,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name"`
	Rules     []BPFRule `json:"rules,omitempty"`
}

// BPFProfile is a workload's default profile, evaluated after every tier falls
// through to pass. Calico profiles carry no tier/kind, just a name and rules.
type BPFProfile struct {
	Name  string    `json:"name"`
	Rules []BPFRule `json:"rules,omitempty"`
}

type BPFRule struct {
	Action      string     `json:"action"`
	MatchID     uint64     `json:"matchID"`
	Protocol    string     `json:"protocol,omitempty"`
	NotProtocol string     `json:"notProtocol,omitempty"`
	Source      *BPFEntity `json:"source,omitempty"`
	Destination *BPFEntity `json:"destination,omitempty"`
	ICMP        *BPFICMP   `json:"icmp,omitempty"`
	NotICMP     *BPFICMP   `json:"notICMP,omitempty"`
}

type BPFEntity struct {
	Nets          []string       `json:"nets,omitempty"`
	NotNets       []string       `json:"notNets,omitempty"`
	IPSets        []BPFIPSet     `json:"ipSets,omitempty"`
	NotIPSets     []BPFIPSet     `json:"notIPSets,omitempty"`
	Ports         []BPFPortRange `json:"ports,omitempty"`
	NotPorts      []BPFPortRange `json:"notPorts,omitempty"`
	NamedPorts    []string       `json:"namedPorts,omitempty"`
	NotNamedPorts []string       `json:"notNamedPorts,omitempty"`
}

// isEmpty reports whether this leg carries no L3/L4 criteria at all, so
// bpfEntity can return nil instead of an empty object for JSON.
func (e *BPFEntity) isEmpty() bool {
	return e == nil || (len(e.Nets) == 0 && len(e.NotNets) == 0 &&
		len(e.IPSets) == 0 && len(e.NotIPSets) == 0 &&
		len(e.Ports) == 0 && len(e.NotPorts) == 0 &&
		len(e.NamedPorts) == 0 && len(e.NotNamedPorts) == 0)
}

// BPFIPSet pairs a selector's IP-set ID with the members the calc graph
// resolved it to (empty if the request captured none).
type BPFIPSet struct {
	ID      string   `json:"id"`
	Members []string `json:"members,omitempty"`
}

// BPFPortRange is a single port or a range (First==Last for a single port).
type BPFPortRange struct {
	First int32 `json:"first"`
	Last  int32 `json:"last"`
}

// BPFICMP is an ICMP match: a type, plus a code when the rule pins one.
type BPFICMP struct {
	Type int32  `json:"type"`
	Code *int32 `json:"code,omitempty"`
}

// BPFResponse is the rendered programs plus feed-time warnings/errors.
type BPFResponse struct {
	Programs []BPFProgram `json:"programs"`
	Warnings []string     `json:"warnings,omitempty"`
	Errors   []string     `json:"errors,omitempty"`
}

// RenderBPF builds the calc graph for req and renders the eBPF policy program
// for each selected endpoint × direction × IP version.
func RenderBPF(req Request, opts BPFOptions) BPFResponse {
	resp := BPFResponse{}

	req, inlineErrs := applyInlineResources(req)

	g := buildGraph(req, nil)
	resp.Warnings = g.warnings
	resp.Errors = append(inlineErrs, g.errors...)

	directions := opts.Directions
	if len(directions) == 0 {
		directions = []string{"ingress", "egress"}
	}
	ipVersions := opts.IPVersions
	if len(ipVersions) == 0 {
		ipVersions = ipVersionsForReq(req)
	}

	for _, id := range sortedKeys(g.wepByID) {
		if !matchesAny(id, opts.Endpoints) {
			continue
		}
		wep := g.wepByID[id]
		for _, ipv := range ipVersions {
			for _, dir := range directions {
				ingress := dir == "ingress"
				rls := polprogRules(wep.GetTiers(), wep.GetProfileIds(), ingress, g.store)
				prog := BPFProgram{
					Endpoint:  id,
					Interface: wep.GetName(),
					Direction: dir,
					IPVersion: ipv,
				}
				// Since Cost is added we need to compile or Peacha goes purr purr purr
				progs, err := compileBPF(rls, ipv)
				if err != nil {
					prog.Error = err.Error()
				}
				prog.SubPrograms = len(progs)
				for _, p := range progs {
					prog.Instructions += len(p)
				}
				if opts.Verbose {
					prog.Lines = renderBPFVerbose(progs)
				} else {
					prog.Tiers, prog.Profiles = bpfTree(rls, g.ipSetMembers, ipv)
				}
				resp.Programs = append(resp.Programs, prog)
			}
		}
	}
	return resp
}

// polprogRules converts an endpoint's resolved tiers + profiles into the
// polprog.Rules the compiler consumes, for one direction. Mirrors the Linux
// dataplane's bpf_ep_mgr.extractTiers/extractProfiles, reading the proto rules
// out of the policystore the calc graph populated.
func polprogRules(tiers []*proto.TierInfo, profileIDs []string, ingress bool, store *policystore.PolicyStore) polprog.Rules {
	dir := rules.RuleDirEgress
	if ingress {
		dir = rules.RuleDirIngress
	}

	var r polprog.Rules
	for _, tier := range tiers {
		pols := tier.GetEgressPolicies()
		if ingress {
			pols = tier.GetIngressPolicies()
		}
		if len(pols) == 0 {
			continue
		}
		pt := polprog.Tier{Name: tier.GetName()}
		stagedOnly := true
		for _, polID := range pols {
			id := types.ProtoToPolicyID(polID)
			if model.KindIsStaged(id.Kind) {
				continue
			}
			pol := store.PolicyByID[id]
			if pol == nil {
				continue
			}
			stagedOnly = false
			prules := pol.GetOutboundRules()
			if ingress {
				prules = pol.GetInboundRules()
			}
			pp := polprog.Policy{Name: id.Name, Namespace: id.Namespace, Kind: id.Kind, Rules: make([]polprog.Rule, len(prules))}
			for ri, pr := range prules {
				pp.Rules[ri] = polprog.Rule{Rule: pr, MatchID: ruleMatchID(dir, pr.GetAction(), rules.RuleOwnerTypePolicy, ri, id)}
			}
			pt.Policies = append(pt.Policies, pp)
		}
		// Workload normal policy drops at end-of-tier unless the tier's
		// default action is Pass (then it falls through to the next tier).
		if !stagedOnly && tier.GetDefaultAction() != "Pass" {
			pt.EndRuleID = nflogID(rules.CalculateEndOfTierDropNFLOGPrefixStr(dir, tier.GetName()))
			pt.EndAction = polprog.TierEndDeny
		} else {
			pt.EndRuleID = nflogID(rules.CalculateEndOfTierPassNFLOGPrefixStr(dir, tier.GetName()))
			pt.EndAction = polprog.TierEndPass
		}
		r.Tiers = append(r.Tiers, pt)
	}

	for _, pn := range profileIDs {
		prof := store.ProfileByID[types.ProfileID{Name: pn}]
		if prof == nil {
			continue
		}
		prules := prof.GetOutboundRules()
		if ingress {
			prules = prof.GetInboundRules()
		}
		pp := polprog.Profile{Name: pn, Rules: make([]polprog.Rule, len(prules))}
		for ri, pr := range prules {
			pp.Rules[ri] = polprog.Rule{Rule: pr, MatchID: ruleMatchID(dir, pr.GetAction(), rules.RuleOwnerTypeProfile, ri, &types.ProfileID{Name: pn})}
		}
		r.Profiles = append(r.Profiles, pp)
	}
	return r
}

// allocOnLookup adapts idalloc to polprog's ipSetIDProvider: the compiler
// looks up IP-set names via GetNoAlloc and panics on a miss (in the live
// dataplane every referenced set was pre-allocated). For a static render we
// allocate on first lookup, giving each set a stable, sequential synthetic ID
// within this program. The concrete numbers differ from a live node (IP-set
// IDs are runtime-assigned) — that's inherent to rendering without a kernel.
type allocOnLookup struct{ a *idalloc.IDAllocator }

func (p allocOnLookup) GetNoAlloc(id string) uint64 { return p.a.GetOrAlloc(id) }

// compileBPF runs "rls" rules through felix's polprog compiler.
func compileBPF(rls polprog.Rules, ipv int) (progs []asm.Insns, err error) {
	defer func() {
		if r := recover(); r != nil {
			progs, err = nil, fmt.Errorf("polprog panic: %v", r)
		}
	}()

	opts := []polprog.Option{
		polprog.WithPolicyDebugEnabled(),
		polprog.WithAllowDenyJumps(bpfAllowJumpIdx, bpfDenyJumpIdx),
	}
	if ipv == 6 {
		opts = append(opts, polprog.WithIPv6())
	}
	// need a dummy here, or kitty scratches
	b := polprog.NewBuilder(allocOnLookup{idalloc.New()}, 1, 2, 3, 4, opts...)
	return b.Instructions(rls)
}

// renderBPFVerbose emits the full annotated disassembly: jump labels,
// per-rule/tier/match comments, and one line per BPF instruction. Equivalent
// to `calico-node bpf policy dump --asm`.
func renderBPFVerbose(progs []asm.Insns) []string {
	var lines []string
	for pi, prog := range progs {
		if len(progs) > 1 {
			lines = append(lines, fmt.Sprintf("# --- sub-program %d/%d ---", pi+1, len(progs)))
		}
		for _, insn := range prog {
			for _, label := range insn.Labels {
				lines = append(lines, label+":")
			}
			for _, c := range insn.Comments {
				if strings.HasPrefix(c, "Match: ") {
					// Positive per-rule summary is concise-only; the asm view
					// already carries the per-criterion "If … skip to next rule"
					// comments inline, so repeating it here is redundant.
					continue
				}
				lines = append(lines, "  ; "+c)
			}
			line := "    " + insn.String()
			if insn.Annotation != "" {
				line += "  ; " + insn.Annotation
			}
			lines = append(lines, line)
		}
	}
	return lines
}

// bpfTree is the new way to figure out how to create the BPF representation that doesn't suck
func bpfTree(rls polprog.Rules, ipSetMembers map[string][]string, ipv int) (tiers []BPFTier, profiles []BPFProfile) {
	for _, t := range rls.Tiers {
		bt := BPFTier{Name: t.Name, Policies: make([]BPFPolicy, 0, len(t.Policies))}
		switch t.EndAction {
		case polprog.TierEndDeny:
			bt.DefaultAction = "deny"
		case polprog.TierEndPass:
			bt.DefaultAction = "pass"
		}
		for _, p := range t.Policies {
			bt.Policies = append(bt.Policies, BPFPolicy{
				Kind:      p.Kind,
				Namespace: p.Namespace,
				Name:      p.Name,
				Rules:     bpfRules(p.Rules, ipSetMembers, ipv),
			})
		}
		tiers = append(tiers, bt)
	}
	for _, p := range rls.Profiles {
		profiles = append(profiles, BPFProfile{Name: p.Name, Rules: bpfRules(p.Rules, ipSetMembers, ipv)})
	}
	return tiers, profiles
}

func bpfRules(rs []polprog.Rule, ipSetMembers map[string][]string, ipv int) []BPFRule {
	if len(rs) == 0 {
		return nil
	}
	out := make([]BPFRule, len(rs))
	for i, r := range rs {
		out[i] = bpfRule(r, ipSetMembers, ipv)
	}
	return out
}

// bpfRule converts one polprog.Rule to its match criteria, filtered to the
// program's IP version — an IPv4 program drops the rule's IPv6 nets and vice
// versa, the same narrowing felix's own rule formatting does.
func bpfRule(r polprog.Rule, ipSetMembers map[string][]string, ipv int) BPFRule {
	action := strings.ToLower(r.Rule.GetAction())
	if action == "" {
		action = "allow"
	}
	br := BPFRule{Action: action, MatchID: uint64(r.MatchID)}

	pr := rules.FilterRuleToIPVersion(uint8(ipv), r.Rule)
	if pr == nil {
		return br // doesn't apply to this IP version: action only, no match
	}
	br.Protocol = protoName(pr.GetProtocol())
	br.NotProtocol = protoName(pr.GetNotProtocol())
	br.Source = bpfEntity(pr.SrcNet, pr.NotSrcNet, pr.SrcIpSetIds, pr.NotSrcIpSetIds,
		pr.SrcPorts, pr.NotSrcPorts, pr.SrcNamedPortIpSetIds, pr.NotSrcNamedPortIpSetIds, ipSetMembers)
	br.Destination = bpfEntity(pr.DstNet, pr.NotDstNet, pr.DstIpSetIds, pr.NotDstIpSetIds,
		pr.DstPorts, pr.NotDstPorts, pr.DstNamedPortIpSetIds, pr.NotDstNamedPortIpSetIds, ipSetMembers)
	br.ICMP = bpfICMP(pr.GetIcmp())
	br.NotICMP = bpfICMP(pr.GetNotIcmp())
	return br
}

// bpfEntity builds one leg's L3/L4 match, resolving each referenced IP set to
// the members the calc graph captured for it. Returns nil when the leg carries
// no criteria at all, so an empty leg drops out of the JSON entirely.
func bpfEntity(nets, notNets, ipSets, notIPSets []string, ports, notPorts []*proto.PortRange,
	namedPorts, notNamedPorts []string, ipSetMembers map[string][]string) *BPFEntity {
	e := &BPFEntity{
		Nets:          nets,
		NotNets:       notNets,
		IPSets:        bpfIPSets(ipSets, ipSetMembers),
		NotIPSets:     bpfIPSets(notIPSets, ipSetMembers),
		Ports:         bpfPortRanges(ports),
		NotPorts:      bpfPortRanges(notPorts),
		NamedPorts:    namedPorts,
		NotNamedPorts: notNamedPorts,
	}
	if e.isEmpty() {
		return nil
	}
	return e
}

// bpfIPSets pairs each set's string ID with the members ipSetMembers (the calc
// graph's raw IPSetUpdate members) captured for it in this Request.
func bpfIPSets(ids []string, ipSetMembers map[string][]string) []BPFIPSet {
	if len(ids) == 0 {
		return nil
	}
	out := make([]BPFIPSet, len(ids))
	for i, id := range ids {
		out[i] = BPFIPSet{ID: id, Members: ipSetMembers[id]}
	}
	return out
}

func bpfPortRanges(prs []*proto.PortRange) []BPFPortRange {
	if len(prs) == 0 {
		return nil
	}
	out := make([]BPFPortRange, len(prs))
	for i, pr := range prs {
		out[i] = BPFPortRange{First: pr.First, Last: pr.Last}
	}
	return out
}

// protoName names a protocol the way felix's own rule formatting does: the
// name when the rule specifies one, else the well-known number→name mapping,
// else the bare decimal number so nothing is silently dropped. "" when unset.
func protoName(p *proto.Protocol) string {
	if p == nil {
		return ""
	}
	switch v := p.GetNumberOrName().(type) {
	case *proto.Protocol_Name:
		return strings.ToLower(v.Name)
	case *proto.Protocol_Number:
		switch v.Number {
		case 1:
			return "icmp"
		case 6:
			return "tcp"
		case 17:
			return "udp"
		case 58:
			return "icmpv6"
		case 132:
			return "sctp"
		default:
			return fmt.Sprintf("%d", v.Number)
		}
	}
	return ""
}

// bpfICMP converts an ICMP oneof (Rule.Icmp or Rule.NotIcmp) to a BPFICMP, or
// nil when the rule doesn't match on ICMP at all.
func bpfICMP(icmp interface{}) *BPFICMP {
	switch v := icmp.(type) {
	case *proto.Rule_IcmpType:
		return &BPFICMP{Type: v.IcmpType}
	case *proto.Rule_IcmpTypeCode:
		code := v.IcmpTypeCode.Code
		return &BPFICMP{Type: v.IcmpTypeCode.Type, Code: &code}
	case *proto.Rule_NotIcmpType:
		return &BPFICMP{Type: v.NotIcmpType}
	case *proto.Rule_NotIcmpTypeCode:
		code := v.NotIcmpTypeCode.Code
		return &BPFICMP{Type: v.NotIcmpTypeCode.Type, Code: &code}
	}
	return nil
}

// ruleMatchID reproduces the dataplane's rule-hit ID: the fnv64a hash of the
// rule's NFLOG prefix (the no-flow-logs path). Surfaces in the program as the
// "Rule MatchID" comment; cosmetic for a static render but kept faithful.
func ruleMatchID(dir rules.RuleDir, action string, owner rules.RuleOwnerType, idx int, id types.IDMaker) polprog.RuleMatchID {
	var a rules.RuleAction
	switch action {
	case "", "allow":
		a = rules.RuleActionAllow
	case "next-tier", "pass":
		a = rules.RuleActionPass
	case "deny":
		a = rules.RuleActionDeny
	default:
		return 0
	}
	return nflogID(rules.CalculateNFLOGPrefixStr(a, owner, dir, idx, id))
}

func nflogID(prefix string) polprog.RuleMatchID {
	h := fnv.New64a()
	_, _ = h.Write([]byte(prefix))
	return h.Sum64()
}

// matchesAny reports whether id contains any of the filter substrings
// (case-insensitive). An empty filter matches everything.
func matchesAny(id string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	lid := strings.ToLower(id)
	for _, f := range filters {
		if f != "" && strings.Contains(lid, strings.ToLower(f)) {
			return true
		}
	}
	return false
}
