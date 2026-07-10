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

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Live-cluster validation of the Calico policy render.
//
// `telepathy cost` weighs the whole dataplane render, most of which is fixed
// per-endpoint scaffolding that scales with the topology, not the policy — so the
// aggregate weight can't be matched to a node's total footprint. This validates
// the part that IS the policy's cost and IS exactly reproducible: the per-policy
// rules Felix programs, counted the same way on the render and on the cluster.
//
// A Calico cluster with Windows nodes runs TWO dataplanes at once: HNS on the
// Windows nodes and iptables/nftables/eBPF on the Linux nodes. One
// GlobalNetworkPolicy is programmed on both — this case's server-win endpoint as
// an HNS ACL, its server-lin endpoint as an iptables chain — so both are a real,
// separate cost. validateCost therefore checks EVERY dataplane the cluster
// actually runs and reports each; a Windows run reports both, a Linux run just
// iptables. Each count comes from Felix's own renderer over the same IP-rewritten
// policy the cluster got, so each matches exactly. What "policy rules" means, and
// how the live side is read, is dataplane-specific:
//
//   - Linux / iptables: rule lines in the per-policy chains cali-pi-<tier>.<name>
//     / cali-po-..., from `telepathy iptables` vs iptables-save. Deduped across
//     nodes (Felix programs a policy chain identically on every node hosting a
//     selected endpoint) by chain name.
//   - Linux / native nftables: the same per-policy chains, but in the `ip calico`
//     nft table (chains layer-prefixed, e.g. filter-cali-pi-<policy>), from
//     `telepathy iptables -backend nftables` vs `nft list table ip calico`. Same
//     enforcing-rule count, deduped by chain name. Distinct from iptables-on-nft:
//     that host has no `ip calico` table, so only one of the two ever reads present.
//   - Windows / HNS: distinct ACL rule Ids prefixed "policy-", from `telepathy
//     hns` vs Get-HnsEndpoint on the Windows node(s). HNS ACLs are per-endpoint
//     flattened lists (no policy-named chains), but each policy-derived rule
//     carries a stable Id, so distinct Ids dedup the rule across endpoints and
//     nodes — and drop the profile/host/default rules that aren't policy cost.
//     The render emits HNS ACLs for every endpoint including Linux ones (which
//     really run on iptables), but a rule shared with a Windows endpoint has the
//     same Id, so distinct-Id counting collapses to what the Windows node
//     actually programs.
//   - Linux / eBPF: policy PROGRAMS, not rules — eBPF compiles the tier set into
//     one program per endpoint x direction, so there are no per-policy chains to
//     count. `telepathy bpf` reports one program per endpoint x direction x IP
//     version; the live count is the attached policy programs from
//     `calico-node -bpf ifstate`. (Instruction counts aren't compared — a
//     JIT-loaded program never matches the render's assembled count; the program
//     count does.) The program count is per-endpoint (unlike the per-policy
//     iptables/HNS counts, which dedup a shared rule across endpoints), so the
//     render is filtered to endpoints on Linux nodes — the ones eBPF actually
//     enforces — via osByID. That lets a mixed Windows+eBPF cluster report bpf
//     (Linux endpoints) AND hns (Windows endpoints) side by side.
//
// The rule readings exclude non-policy rules (profile / host / default-deny / the
// render's comment-only markers), so the count is the policy's own contribution.
// A pre-policy baseline is subtracted so any resting system policies don't count.
// Opt in per case with `cost: true` in meta.yaml; Calico only.
//
// iptables, native nftables, eBPF, and HNS are covered.

// policyRuleCounts is the live per-dataplane policy-cost tally. present flags say
// which dataplanes the cluster actually runs (and could be read), so validateCost
// checks exactly those. The Linux node runs one of iptables / native nftables /
// eBPF (mutually exclusive — each reader keys off state the other two don't
// produce: iptables-save `-A cali-` lines, an `ip calico` nft table, eBPF
// ifstate programs), plus HNS on any Windows node.
//
// The unit differs by dataplane: iptables/hns count policy *rules* (chain rules /
// ACL Ids), bpf counts policy *programs* — eBPF has no per-policy chains (the tier
// set compiles into one program per endpoint x direction), so the program count
// is its cost unit. `telepathy bpf` reports instruction counts too, but those
// can't match a JIT-loaded program, whereas the program count is exact.
type policyRuleCounts struct {
	iptables, nft, hns, bpf                          int
	linuxPresent, nftPresent, hnsPresent, bpfPresent bool
}

// policyRuleCounts reads every dataplane the cluster runs. Absent dataplanes
// return present=false and are skipped: HNS on a cluster with no Windows node,
// iptables on an eBPF (or nftables) node, bpf on an iptables node.
func (c *cluster) policyRuleCounts(ctx context.Context) (policyRuleCounts, error) {
	ipt, linuxPresent, err := c.iptablesPolicyRuleCount(ctx)
	if err != nil {
		return policyRuleCounts{}, err
	}
	nft, nftPresent, err := c.nftPolicyRuleCount(ctx)
	if err != nil {
		return policyRuleCounts{}, err
	}
	hns, hnsPresent, err := c.hnsPolicyRuleCount(ctx)
	if err != nil {
		return policyRuleCounts{}, err
	}
	bpf, bpfPresent, err := c.bpfPolicyProgramCount(ctx)
	if err != nil {
		return policyRuleCounts{}, err
	}
	// iptables XOR eBPF: in eBPF mode Felix still programs iptables cali- chains
	// (host/failsafe), so `-A cali-` lines exist and linuxPresent trips — but
	// workload policy compiles into eBPF, not cali-pi/po chains. Counting iptables
	// policy rules there is meaningless (live delta is 0 while the render predicts
	// N), and it double-reports alongside bpf. eBPF is the Linux policy dataplane
	// when present, so it wins.
	if bpfPresent {
		linuxPresent = false
	}
	return policyRuleCounts{ipt, nft, hns, bpf, linuxPresent, nftPresent, hnsPresent, bpfPresent}, nil
}

// bpfPolicyProgramCount counts the policy programs Felix has attached to workload
// interfaces across the Linux nodes, from `calico-node -bpf ifstate` — one per
// (interface, direction, IP version) with a non -1 policy-program index. That is
// the eBPF analog of a per-policy chain/ACL: the render's program count must
// equal it. present is true only in eBPF mode (ifstate lists workload interfaces
// with policy programs) — an iptables node has none.
//
// This reads only the Linux nodes' workload interfaces, so it already counts just
// the endpoints eBPF enforces; the render side is filtered to those same (Linux)
// endpoints via osByID, so bpf and hns line up side by side on a mixed
// Windows+eBPF cluster.
func (c *cluster) bpfPolicyProgramCount(ctx context.Context) (programs int, present bool, err error) {
	nodes, err := c.nodes(ctx)
	if err != nil {
		return 0, false, err
	}
	win, _ := c.windowsNodes(ctx)
	for node := range nodes {
		if win[node] {
			continue
		}
		pod := nodeCalicoPod(ctx, c, "k8s-app=calico-node", node)
		if pod == "" {
			continue
		}
		out, xerr := c.exec(ctx, "calico-system", pod, "calico-node",
			"calico-node", "-bpf", "ifstate", "dump")
		if xerr != nil && strings.TrimSpace(out) == "" {
			continue // not eBPF mode / unreachable
		}
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "flags: workload") {
				continue
			}
			present = true
			for _, key := range []string{"IngressPolicyV4:", "EgressPolicyV4:", "IngressPolicyV6:", "EgressPolicyV6:"} {
				if v := ifstateField(line, key); v != "" && v != "-1" {
					programs++
				}
			}
		}
	}
	return programs, present, nil
}

// ifstateField returns the token following key on an ifstate line (e.g.
// "IngressPolicyV4: 10," -> "10"), stopping at the first delimiter.
func ifstateField(line, key string) string {
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[i+len(key):])
	if j := strings.IndexAny(rest, ", }"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// iptablesPolicyRuleCount sums the rules in the distinct Calico per-policy chains
// (cali-pi-* / cali-po-*) across every Linux node, deduped by chain name — a
// chain programmed on N nodes is counted once (its rule count is identical on
// each). present reports whether ANY cali- rule was seen: false means the cluster
// isn't on the iptables backend (no `-A cali-` lines), so the caller skips.
func (c *cluster) iptablesPolicyRuleCount(ctx context.Context) (rules int, present bool, err error) {
	nodes, err := c.nodes(ctx)
	if err != nil {
		return 0, false, err
	}
	win, _ := c.windowsNodes(ctx) // non-fatal: an all-Linux cluster returns empty
	perChain := map[string]int{}  // chain name -> rule count (deduped across nodes)
	for node := range nodes {
		if win[node] {
			continue
		}
		out, derr := c.dockerExec(ctx, node, "iptables-save")
		if derr != nil && strings.TrimSpace(out) == "" {
			continue // node unreachable / no iptables-save; a partial count beats none
		}
		nodeChain := map[string]int{}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "-A cali-") {
				present = true
			}
			if isPolicyRuleLine(line) {
				if f := strings.Fields(line); len(f) >= 2 {
					nodeChain[f[1]]++
				}
			}
		}
		// Take the per-chain max across nodes: identical everywhere it's present,
		// so max == the chain's rule count without summing duplicate copies.
		for name, n := range nodeChain {
			if n > perChain[name] {
				perChain[name] = n
			}
		}
	}
	for _, n := range perChain {
		rules += n
	}
	return rules, present, nil
}

// nftPolicyRuleCount is the native-nftables analog of iptablesPolicyRuleCount:
// it sums the enforcing rules in the Calico per-policy chains (cali-pi-* /
// cali-po-*) across the Linux nodes, deduped by chain name, read from `nft list
// table ip calico` — the single base table Felix's nftables dataplane programs
// (family ip, name "calico"; layer chains are prefixed, e.g.
// filter-cali-pi-<policy>). present is true only in native nftables mode: that
// table exists only then. An iptables-on-nft-backend host (Calico's iptables
// dataplane on a modern kernel) has NO `ip calico` table — its cali chains live
// in the standard filter/nat tables — so this stays present=false there and the
// iptables reader handles it, keeping the two mutually exclusive.
func (c *cluster) nftPolicyRuleCount(ctx context.Context) (rules int, present bool, err error) {
	nodes, err := c.nodes(ctx)
	if err != nil {
		return 0, false, err
	}
	win, _ := c.windowsNodes(ctx)
	perChain := map[string]int{} // chain name -> rule count (deduped across nodes)
	for node := range nodes {
		if win[node] {
			continue
		}
		out, derr := c.dockerExec(ctx, node, "nft", "list", "table", "ip", "calico")
		if derr != nil && strings.TrimSpace(out) == "" {
			continue // table absent => not native nftables mode; a partial count beats none
		}
		if strings.Contains(out, "cali-") {
			present = true
		}
		for name, n := range nftPolicyRuleChains(out) {
			if n > perChain[name] {
				perChain[name] = n
			}
		}
	}
	for _, n := range perChain {
		rules += n
	}
	return rules, present, nil
}

// nftPolicyRuleChains parses `nft list`/render output and returns, per Calico
// per-policy chain (name contains cali-pi- / cali-po-, excluding the cali-pri- /
// cali-pro- profile chains), its count of ENFORCING rules. It drives both the
// live count and the render count so the two are strictly comparable. A chain's
// rules are the lines between its `chain <name> {` and closing `}`. The
// comment-only marker Felix emits for an unpoliced direction renders as a bare
// `continue` (live adds a comment; the render omits the chain live but emits it
// on paper) — it carries no policy cost and is excluded, the nft analog of the
// iptables reader's jump/goto gate.
func nftPolicyRuleChains(dump string) map[string]int {
	perChain := map[string]int{}
	chain := ""
	policy := false
	for _, raw := range strings.Split(dump, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "chain "):
			chain = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "chain ")), " {")
			policy = strings.Contains(chain, "cali-pi-") || strings.Contains(chain, "cali-po-")
			if policy {
				perChain[chain] += 0 // register the chain even if it holds only a marker
			}
		case line == "}":
			chain, policy = "", false
		case policy && isNftEnforcingRule(line):
			perChain[chain]++
		}
	}
	return perChain
}

// isNftEnforcingRule reports whether an nft rule line does real work, i.e. is not
// the bare `continue` fall-through marker. It strips a trailing `comment "..."`
// and a leading counter clause (`counter` or `counter packets N bytes N`, and the
// bare `packets N bytes N` form some nft versions print) before the test, so
// `counter meta mark set ...` (an allow's set-mark) counts while `continue` /
// `counter packets 0 bytes 0 continue` does not.
func isNftEnforcingRule(line string) bool {
	if i := strings.Index(line, " comment \""); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) > 0 && f[0] == "counter" {
		if len(f) >= 5 && f[1] == "packets" && f[3] == "bytes" {
			f = f[5:]
		} else {
			f = f[1:]
		}
	} else if len(f) >= 4 && f[0] == "packets" && f[2] == "bytes" {
		f = f[4:]
	}
	return len(f) > 0 && strings.Join(f, " ") != "continue"
}

// hnsPolicyRuleCount counts the distinct policy-derived HNS ACL rules (Id prefix
// "policy-") programmed across the Windows node(s), read from Get-HnsEndpoint in
// each calico-node-windows pod. Distinct Ids dedup a rule shared across endpoints
// / nodes. present reports whether a Windows calico-node pod was reachable at all
// (false => nothing to read, caller skips).
func (c *cluster) hnsPolicyRuleCount(ctx context.Context) (rules int, present bool, err error) {
	// HNS is only exercised when the run schedules the case's pods onto Windows
	// nodes (E2E_OS=windows). On a Linux run a lingering Windows node still exists,
	// but the case has no Windows endpoints — so its policy is never programmed as
	// HNS ACLs, while `telepathy hns` would still render ACLs for the Linux
	// endpoints. Gating on the run OS keeps that from reading as a false divergence.
	if cfg.OS != "windows" {
		return 0, false, nil
	}
	win, err := c.windowsNodes(ctx)
	if err != nil {
		return 0, false, err
	}
	// One line per ACL rule Id; blanks (default-block rules) are dropped by the
	// prefix filter below.
	const psListACLIds = `Get-HnsEndpoint | ForEach-Object { $_.Policies } | ` +
		`Where-Object { "$($_.Type)" -eq "ACL" } | ForEach-Object { $_.Id }`
	ids := map[string]bool{} // distinct policy Ids across all Windows nodes
	for node := range win {
		pod := nodeCalicoPod(ctx, c, "k8s-app=calico-node-windows", node)
		if pod == "" {
			continue
		}
		out, xerr := c.exec(ctx, "calico-system", pod, "node",
			"powershell", "-NoProfile", "-NonInteractive", "-Command", psListACLIds)
		if xerr != nil && strings.TrimSpace(out) == "" {
			continue
		}
		present = true
		for _, line := range strings.Split(out, "\n") {
			if id := strings.TrimSpace(line); strings.HasPrefix(id, "policy-") {
				ids[id] = true
			}
		}
	}
	return len(ids), present, nil
}

// renderedChains is the subset of `telepathy iptables -json` output this check
// needs (a local mirror so the e2e package stays free of the provider package).
type renderedChains struct {
	Dataplanes []struct {
		Tables []struct {
			Chains []struct {
				Name  string   `json:"name"`
				Lines []string `json:"lines"`
			} `json:"chains"`
		} `json:"tables"`
	} `json:"dataplanes"`
}

func renderedIptablesPolicyRules(ctx context.Context, topo, policyFile string) (int, error) {
	out, err := runRender(ctx, topo, policyFile, "iptables")
	if err != nil {
		return 0, err
	}
	var r renderedChains
	if err := json.Unmarshal(out, &r); err != nil {
		return 0, fmt.Errorf("iptables render not JSON: %v", err)
	}
	rules := 0
	for _, dp := range r.Dataplanes {
		for _, t := range dp.Tables {
			for _, ch := range t.Chains {
				for _, line := range ch.Lines {
					if isPolicyRuleLine(line) {
						rules++
					}
				}
			}
		}
	}
	return rules, nil
}

// renderedHNS is the subset of `telepathy hns -json` output this check needs.
type renderedHNS struct {
	Endpoints []struct {
		Rules []struct {
			Id string `json:"Id"`
		} `json:"rules"`
	} `json:"endpoints"`
}

// renderedBPFPrograms counts the eBPF policy programs `telepathy bpf` would load
// (one per endpoint x direction x IP version) — the render side of the program
// count bpfPolicyProgramCount reads live. It counts only programs for endpoints
// on Linux nodes (osByID[endpoint] == "linux"), since eBPF enforces only those;
// the render emits a program for every topology endpoint, including Windows ones
// that really run on HNS.
func renderedBPFPrograms(ctx context.Context, topo, policyFile string, osByID map[string]string) (int, error) {
	out, err := runRender(ctx, topo, policyFile, "bpf")
	if err != nil {
		return 0, err
	}
	var r struct {
		Programs []struct {
			Endpoint string `json:"endpoint"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return 0, fmt.Errorf("bpf render not JSON: %v", err)
	}
	n := 0
	for _, p := range r.Programs {
		if osByID[p.Endpoint] == "linux" {
			n++
		}
	}
	return n, nil
}

// renderedNftPolicyRules counts the enforcing per-policy-chain rules
// `telepathy iptables -backend nftables` would program — the render side of the
// count nftPolicyRuleCount reads live. The nft render reuses renderedChains, but
// each chain's Lines include the `chain {...}` wrapper, so the same
// nftPolicyRuleChains parser that reads live output reads the render's lines too.
func renderedNftPolicyRules(ctx context.Context, topo, policyFile string) (int, error) {
	out, err := runRender(ctx, topo, policyFile, "iptables", "-backend", "nftables")
	if err != nil {
		return 0, err
	}
	var r renderedChains
	if err := json.Unmarshal(out, &r); err != nil {
		return 0, fmt.Errorf("nftables render not JSON: %v", err)
	}
	rules := 0
	for _, dp := range r.Dataplanes {
		for _, t := range dp.Tables {
			for _, ch := range t.Chains {
				for _, n := range nftPolicyRuleChains(strings.Join(ch.Lines, "\n")) {
					rules += n
				}
			}
		}
	}
	return rules, nil
}

func renderedHNSPolicyRules(ctx context.Context, topo, policyFile string) (int, error) {
	out, err := runRender(ctx, topo, policyFile, "hns")
	if err != nil {
		return 0, err
	}
	var r renderedHNS
	if err := json.Unmarshal(out, &r); err != nil {
		return 0, fmt.Errorf("hns render not JSON: %v", err)
	}
	ids := map[string]bool{} // distinct policy Ids, matching the live side
	for _, ep := range r.Endpoints {
		for _, rule := range ep.Rules {
			if strings.HasPrefix(rule.Id, "policy-") {
				ids[rule.Id] = true
			}
		}
	}
	return len(ids), nil
}

// runRender runs `telepathy <subcmd> -json` over the topology (stdin) and policy,
// mirroring runEngine's invocation shape, and returns raw stdout.
func runRender(ctx context.Context, topo, policyFile, subcmd string, extra ...string) ([]byte, error) {
	argv := append([]string{subcmd, "-provider", cfg.Provider, "-json", "-policy", policyFile}, extra...)
	cmd := exec.CommandContext(ctx, cfg.TelepathyBin, argv...)
	cmd.Stdin = strings.NewReader(topo)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("telepathy %s (exit %v): %s", subcmd, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// isPolicyRuleLine reports whether an iptables line is an ENFORCING rule (`-A`
// with a jump/goto target) in a Calico per-policy chain. The same test drives
// both the live count and the render count so the two are strictly comparable.
// Two kinds of line are excluded, on both sides, because neither carries policy
// cost: a chain's `:name - [0:0]` declaration, and the comment-only marker rule
// the render emits for a direction with no rules (e.g. the egress chain of an
// ingress-only policy) — which Felix doesn't program into the live dataplane.
// iptables-save writes the action as `-j` / `-g`; telepathy's render uses the
// long `--jump` / `--goto`, so both spellings are matched.
func isPolicyRuleLine(line string) bool {
	if !strings.HasPrefix(line, "-A cali-pi-") && !strings.HasPrefix(line, "-A cali-po-") {
		return false
	}
	return strings.Contains(line, " -j ") || strings.Contains(line, " --jump ") ||
		strings.Contains(line, " -g ") || strings.Contains(line, " --goto ")
}

// validateCost compares the policy rules the render predicts against the ones the
// live cluster actually programmed for this case, once per dataplane the cluster
// runs. baseline is the per-dataplane count captured before the case's policy was
// applied; the delta (Felix has converged by now — post-settle, post-probe) is
// this case's exact contribution. Because each count comes from the same Felix
// renderer over the same policy, each must match exactly — a mismatch means the
// offline render diverged from what that dataplane programs.
func validateCost(ctx context.Context, t *testing.T, c *cluster, baseline policyRuleCounts, topo, policyFile string, osByID map[string]string) {
	after, err := c.policyRuleCounts(ctx)
	if err != nil {
		t.Errorf("cost: count live policy rules: %v", err)
		return
	}
	// One comparison per dataplane the cluster actually runs. A mixed Windows
	// cluster reports both; a Linux cluster reports iptables alone.
	check := func(dataplane, unit string, render func() (int, error), base, aft int) {
		rendered, rerr := render()
		if rerr != nil {
			t.Errorf("cost (%s): render failed: %v", dataplane, rerr)
			return
		}
		delta := aft - base
		t.Logf("cost (%s): rendered %d policy %s; cluster programmed +%d (baseline %d -> %d)",
			dataplane, rendered, unit, delta, base, aft)
		if rendered != delta {
			t.Errorf("cost (%s): rendered %d policy %s but the cluster programmed %d — the Calico policy render diverges from the dataplane",
				dataplane, rendered, unit, delta)
		}
	}

	if baseline.linuxPresent {
		check("iptables", "rules",
			func() (int, error) { return renderedIptablesPolicyRules(ctx, topo, policyFile) },
			baseline.iptables, after.iptables)
	}
	if baseline.nftPresent {
		check("nftables", "rules",
			func() (int, error) { return renderedNftPolicyRules(ctx, topo, policyFile) },
			baseline.nft, after.nft)
	}
	if baseline.hnsPresent {
		check("hns", "rules",
			func() (int, error) { return renderedHNSPolicyRules(ctx, topo, policyFile) },
			baseline.hns, after.hns)
	}
	if baseline.bpfPresent {
		check("bpf", "programs",
			func() (int, error) { return renderedBPFPrograms(ctx, topo, policyFile, osByID) },
			baseline.bpf, after.bpf)
	}
}
