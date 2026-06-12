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

package engine

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
	// Verbose, when true, emits the full annotated eBPF disassembly (one line
	// per instruction, plus labels and per-match comments) — the same artifact
	// `calico-node bpf policy dump --asm` prints. When false (default), Lines
	// holds the concise tier→policy→rule tree that `calico-node bpf policy
	// dump` prints without --asm.
	Verbose bool
}

// BPFProgram is the rendered policy program for one (endpoint, direction,
// ipVersion). Lines is, by default, the concise tier→policy→rule tree (the
// `calico-node bpf policy dump` view); with BPFOptions.Verbose it is the full
// annotated disassembly: jump labels, per-rule/tier comments, and one line per
// BPF instruction (the `--asm` view). SubPrograms is >1 when polprog had to
// split the program across trampoline boundaries (large policies).
type BPFProgram struct {
	Endpoint    string   `json:"endpoint"`
	Interface   string   `json:"interface"`
	Direction   string   `json:"direction"`
	IPVersion   int      `json:"ipVersion"`
	SubPrograms int      `json:"subPrograms"`
	Lines       []string `json:"lines"`
	Error       string   `json:"error,omitempty"`
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
				lines, n, err := renderBPFProgram(rls, ipv, opts.Verbose)
				if err != nil {
					prog.Error = err.Error()
				}
				prog.Lines = lines
				prog.SubPrograms = n
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

// renderBPFProgram compiles polprog.Rules and renders the result to text.
// Returns (lines, subProgramCount, error). PolicyDebug is enabled so each
// instruction carries the rule/tier/policy comment that both render modes key
// off. With verbose, Lines is the full annotated disassembly; otherwise it's
// the concise tier→policy→rule tree. polprog uses logrus.Panic for some error
// paths, so we recover and report per program rather than crashing the whole
// render.
func renderBPFProgram(rls polprog.Rules, ipv int, verbose bool) (lines []string, n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			lines, n, err = nil, 0, fmt.Errorf("polprog panic: %v", r)
		}
	}()

	opts := []polprog.Option{
		polprog.WithPolicyDebugEnabled(),
		polprog.WithAllowDenyJumps(bpfAllowJumpIdx, bpfDenyJumpIdx),
	}
	if ipv == 6 {
		opts = append(opts, polprog.WithIPv6())
	}
	// Dummy map FDs (1..4) + an allocate-on-lookup IP-set ID provider: the
	// compiler embeds these as constants, so no kernel/maps are needed.
	b := polprog.NewBuilder(allocOnLookup{idalloc.New()}, 1, 2, 3, 4, opts...)
	progs, err := b.Instructions(rls)
	if err != nil {
		return nil, 0, err
	}

	if verbose {
		return renderBPFVerbose(progs), len(progs), nil
	}
	return renderBPFConcise(progs), len(progs), nil
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

// renderBPFConcise walks the policy-debug comments polprog attaches to each
// instruction and prints the tier→policy→rule tree, dropping the individual
// eBPF instructions and per-match plumbing. This mirrors `calico-node bpf
// policy dump` (without --asm); see felix/cmd/calico-bpf/commands/policy_debug.go.
// Rule hit counts are omitted: those come from a live BPF counters map, which a
// static render has no equivalent of. IP-set IDs are the synthetic
// allocOnLookup numbers (no kernel map to resolve them against), so they're
// shown as their hex IDs.
func renderBPFConcise(progs []asm.Insns) []string {
	var lines []string
	depth := 0
	inPolicy := false // inside a "Start of <Kind> …" / "End of …" policy block
	lastProfile := "" // dedupe the synthetic Profile header (repeated per rule)
	for _, prog := range progs {
		for _, insn := range prog {
			for _, c := range insn.Comments {
				switch {
				case strings.HasPrefix(c, "Start of tier "):
					depth = 1
					lines = append(lines, indent(depth)+"Tier: "+strings.TrimPrefix(c, "Start of tier "))
				case strings.HasPrefix(c, "End of tier "):
					lines = append(lines, indent(depth)+formatTierEnd(c))
					depth, inPolicy = 0, false
				case strings.HasPrefix(c, "Start of rule "):
					// Inside a policy, rules nest under it (depth 3). Profile
					// rules carry no enclosing "Start of <Kind>" marker; surface
					// the owning profile name as a depth-1 header and nest the
					// rules one level under it (depth 2) so they aren't orphaned.
					depth = 3
					if !inPolicy {
						if name := ruleOwner(c); name != "" && name != lastProfile {
							lines = append(lines, indent(1)+"Profile: "+name)
							lastProfile = name
						}
						depth = 2
					}
					lines = append(lines, indent(depth)+formatRuleStart(c))
				case strings.HasPrefix(c, "End of rule "):
					if inPolicy {
						depth = 2
					}
				case strings.HasPrefix(c, "IPSets "):
					lines = append(lines, indent(depth)+formatIPSets(c))
				case strings.HasPrefix(c, "#####"):
					// program-split banner: verbose-only.
				case strings.HasPrefix(c, "Start of "):
					depth, inPolicy = 2, true
					lines = append(lines, indent(depth)+"Policy: "+strings.TrimPrefix(c, "Start of "))
				case strings.HasPrefix(c, "End of "):
					lines = append(lines, indent(depth)+"End Policy: "+strings.TrimPrefix(c, "End of "))
					depth, inPolicy = 1, false
				default:
					// Per-match ("If protocol == …") and "Rule MatchID" comments
					// are verbose-only.
				}
			}
		}
	}
	return lines
}

// The helpers below are ported from felix/cmd/calico-bpf/commands/policy_debug.go
// so the editor's concise render matches `calico-node bpf policy dump` byte for
// byte (minus hit counts / IP-set resolution, which need a live node).

// indent returns two spaces per nesting level (0=top, 1=tier, 2=policy, 3=rule).
func indent(depth int) string { return strings.Repeat("  ", depth) }

// ruleOwner returns the first token after "Start of rule " — the owning
// policy/profile's namespaced name.
func ruleOwner(comment string) string {
	after := strings.TrimPrefix(comment, "Start of rule ")
	return strings.SplitN(after, " ", 2)[0]
}

// extractProtoField pulls a quoted field out of a protobuf text-format string,
// e.g. extractProtoField(`action:"allow" protocol:{number:6}`, "action") == "allow".
func extractProtoField(s, field string) string {
	prefix := field + `:"`
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// formatRuleStart turns `Start of rule default/allow-tcp action:"allow" …` into
// `Rule: default/allow-tcp  Action: allow`. An absent action means allow.
func formatRuleStart(comment string) string {
	after := strings.TrimPrefix(comment, "Start of rule ")
	parts := strings.SplitN(after, " ", 2)
	name := parts[0]
	action := "allow"
	if len(parts) == 2 {
		if a := extractProtoField(parts[1], "action"); a != "" {
			action = a
		}
	}
	return fmt.Sprintf("Rule: %s  Action: %s", name, action)
}

// formatIPSets turns `IPSets src_ip_set_ids:<0x..> dst_ip_set_ids:<0x..>` into
// `IP sets: src=0x.. dst=0x..`. (A live node would resolve the IDs to members;
// a static render only has the synthetic IDs.)
func formatIPSets(comment string) string {
	after := strings.TrimPrefix(comment, "IPSets ")
	r := strings.NewReplacer(
		"src_ip_set_ids:<", "src=",
		"dst_ip_set_ids:<", "dst=",
		"not_src_ip_set_ids:<", "!src=",
		"not_dst_ip_set_ids:<", "!dst=",
		">", "",
		" ,", ",",
	)
	return "IP sets: " + strings.TrimSpace(r.Replace(after))
}

// formatTierEnd turns `End of tier default: pass` into
// `End Tier: default  (action: pass)`.
func formatTierEnd(comment string) string {
	after := strings.TrimPrefix(comment, "End of tier ")
	parts := strings.SplitN(after, ": ", 2)
	if len(parts) == 2 {
		return fmt.Sprintf("End Tier: %s  (action: %s)", parts[0], parts[1])
	}
	return "End Tier: " + after
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
