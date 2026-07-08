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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/frozenprocess/telepathy/api"
)

// diagInputs is everything collectDiagnostics needs to reconstruct a failure:
// the exact IP-rewritten inputs the cluster and the engine each saw, the engine's
// verdict, the comparison, and which namespaces hold the case's objects.
type diagInputs struct {
	name          string
	appliedPolicy string              // IP-rewritten policy actually applied to the cluster
	engineTopo    string              // IP-rewritten topology fed to `telepathy test`
	engineReport  api.AssertionReport // engine's per-assertion verdicts
	engineStderr  string
	rep           *caseReport // the three-way comparison (incl. captured probe output)
	namespaces    []string    // case namespaces to snapshot before teardown reaps them
}

// collectDiagnostics dumps a post-mortem for one failed case. It is meant to run
// from a t.Cleanup registered AFTER the teardown closure — cleanups run LIFO, so
// this fires first, while the case's policy/pods/namespaces are still live. When
// cfg.ArtifactRoot (E2E_ARTIFACTS) is unset it only points the reader at how to
// enable capture (the failed-row probe output is already in the test log via
// caseReport.render).
func collectDiagnostics(ctx context.Context, t *testing.T, c *cluster, in diagInputs) {
	root := cfg.ArtifactRoot
	if root == "" {
		t.Logf("set E2E_ARTIFACTS=<dir> to capture per-failure diagnostics (applied inputs, engine report, live cluster state)")
		return
	}
	dir := filepath.Join(root, sanitizeName(in.name))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("artifacts: mkdir %s: %v", dir, err)
		return
	}
	write := func(fn, content string) {
		p := filepath.Join(dir, fn)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Logf("artifacts: mkdir %s: %v", filepath.Dir(p), err)
			return
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Logf("artifacts: write %s: %v", p, err)
		}
	}

	// 1. The exact inputs the cluster and the engine evaluated. Re-running
	//    `telepathy test -policy applied-policy.yaml < engine-topology.yaml`
	//    reproduces the engine's side of the disagreement offline.
	write("applied-policy.yaml", in.appliedPolicy)
	write("engine-topology.yaml", in.engineTopo)
	if b, err := json.MarshalIndent(in.engineReport, "", "  "); err == nil {
		write("engine-report.json", string(b)+"\n")
	}
	if strings.TrimSpace(in.engineStderr) != "" {
		write("engine-stderr.txt", in.engineStderr)
	}

	// 2. The three-way comparison, including the raw probe output for failed rows.
	//    Nil when the case failed before the probe phase (e.g. apply/engine error);
	//    the other artifacts still explain those.
	if in.rep != nil {
		write("comparison.txt", in.rep.render())
	}

	// 3. Live cluster state, captured before teardown deletes it.
	write("cluster-state.txt", clusterStateDump(ctx, c, in.namespaces))
	write("applied-policies.yaml", policyDump(ctx, c))

	// 4. The dataplane's own view — Felix's logs and the programmed packet-filter
	//    ruleset, per node. This is the ground truth a DIFF is a disagreement
	//    about: it shows what the dataplane actually did, vs. what the engine
	//    predicted it would. Calico-specific (Felix + cali-* iptables chains).
	if cfg.Provider == "calico" {
		for _, nd := range calicoDataplaneDump(ctx, c) {
			write(filepath.Join("felix-logs", sanitizeName(nd.name)+".txt"), nd.felix)
			write(filepath.Join("dataplane-rules", sanitizeName(nd.name)+".txt"), nd.rules)
		}
	}

	// Report the absolute path: `go test` runs in the e2e/ package dir, so a
	// relative E2E_ARTIFACTS (e.g. "logs/") lands under e2e/, not the directory
	// `make` was invoked from — a common "where did my artifacts go?" surprise.
	shown := dir
	if abs, err := filepath.Abs(dir); err == nil {
		shown = abs
	}
	t.Logf("failure diagnostics written to %s", shown)
}

// clusterStateDump snapshots the case namespaces: pod placement/readiness, the
// full pod descriptions (restart reasons, conditions, events on the object), and
// recent namespace events. Each section tolerates its own error — a partial dump
// beats none.
func clusterStateDump(ctx context.Context, c *cluster, namespaces []string) string {
	var b strings.Builder
	section := func(title string, args ...string) {
		out, err := c.kubectl(ctx, nil, args...)
		writeKubectlSection(&b, title, out, err)
	}
	for _, ns := range namespaces {
		section("get pods -o wide ("+ns+")", "get", "pods", "-n", ns, "-o", "wide")
		section("describe pods ("+ns+")", "describe", "pods", "-n", ns)
		section("events ("+ns+")", "get", "events", "-n", ns, "--sort-by=.lastTimestamp")
	}
	return b.String()
}

// policyDump fetches the applied policy objects as the apiserver sees them — the
// authoritative view of what the dataplane is enforcing, which is exactly the
// thing an engine!=cluster DIFF is a disagreement about. The kind list is
// provider-aware; missing kinds (e.g. Calico CRDs on an Antrea cluster) surface
// as a captured kubectl error rather than aborting the dump.
func policyDump(ctx context.Context, c *cluster) string {
	kinds := []string{"networkpolicies.networking.k8s.io"} // k8s NetworkPolicy: both providers
	switch cfg.Provider {
	case "calico":
		kinds = append(kinds,
			"networkpolicies.projectcalico.org",
			"globalnetworkpolicies.projectcalico.org",
			"stagedglobalnetworkpolicies.projectcalico.org",
			"tiers.projectcalico.org",
			"hostendpoints.projectcalico.org",
			"networksets.projectcalico.org",
			"globalnetworksets.projectcalico.org",
		)
	case "antrea":
		kinds = append(kinds,
			"clusternetworkpolicies.crd.antrea.io",
			"tiers.crd.antrea.io",
		)
	}
	var b strings.Builder
	for _, kind := range kinds {
		out, err := c.kubectl(ctx, nil, "get", kind, "--all-namespaces", "-o", "yaml")
		writeKubectlSection(&b, kind, out, err)
	}
	return b.String()
}

// calicoDataplaneDump captures, per node, the two things that explain a DIFF on
// a Calico cluster: Felix's recent logs (which policy it resolved and any
// programming errors) and the programmed dataplane ruleset (what actually
// allows/denies the probe). Both are OS-specific:
//
//   - Linux: felix runs in the calico-node pod (calico-system DaemonSet); the
//     ruleset is the cali-* iptables/nft chains, read from the kind node's
//     container since the rendered state isn't reachable through kubectl.
//   - Windows: felix runs in the calico-node-windows pod (container "node"); the
//     ruleset is the HNS policy list, read via kubectl exec since the Windows
//     node is a QEMU VM, not a docker container (dockerExec can't reach it).
//
// Every step tolerates its own error so one unreachable node doesn't sink the
// whole dump. Results are per node: the caller writes one felix-logs/<node>.txt
// and one dataplane-rules/<node>.txt per entry.
func calicoDataplaneDump(ctx context.Context, c *cluster) []nodeDiag {
	nodes, err := c.nodes(ctx)
	if err != nil {
		return []nodeDiag{{name: "list-nodes-error", felix: fmt.Sprintf("(list nodes failed: %v)\n", err)}}
	}
	// Stable, deterministic node order (cleanups shouldn't depend on map order).
	names := make([]string, 0, len(nodes))
	for n := range nodes {
		names = append(names, n)
	}
	sort.Strings(names)

	// windowsNodes error is non-fatal: an all-Linux cluster returns an empty set,
	// and a lookup failure just means we treat every node as Linux (the common case).
	win, _ := c.windowsNodes(ctx)

	out := make([]nodeDiag, 0, len(names))
	for _, node := range names {
		var fb, rb strings.Builder
		if win[node] {
			windowsNodeDump(ctx, c, node, &fb, &rb)
		} else {
			linuxNodeDump(ctx, c, node, &fb, &rb)
		}
		out = append(out, nodeDiag{name: node, felix: fb.String(), rules: rb.String()})
	}
	return out
}

// nodeDiag is one node's dataplane post-mortem: its felix logs and its
// programmed ruleset, each destined for its own file.
type nodeDiag struct {
	name  string
	felix string
	rules string
}

// felixTail is generous on purpose: calico-node is extremely chatty, and the
// policy-programming lines that explain a DIFF are easily pushed past a small
// tail by routine per-node churn (route/typha/BGP logs).
const felixTail = "3000"

// linuxNodeDump appends one Linux node's felix logs and cali-* ruleset.
func linuxNodeDump(ctx context.Context, c *cluster, node string, fb, rb *strings.Builder) {
	fmt.Fprintf(fb, "=== felix @ %s ===\n", node)
	pod := nodeCalicoPod(ctx, c, "k8s-app=calico-node", node)
	if pod == "" {
		fmt.Fprintf(fb, "(no calico-node pod found on %s)\n\n", node)
	} else {
		appendPodLogs(ctx, c, fb, pod, "calico-node", node)
	}

	// Ruleset: read from the kind node container. Calico may use the iptables
	// or the nft backend depending on version/config, so try both families
	// and keep whatever the node answers — a failed variant is just noise.
	for _, argv := range [][]string{
		{"iptables-save"},
		{"ip6tables-save"},
		{"nft", "list", "ruleset"},
	} {
		out, derr := c.dockerExec(ctx, node, argv...)
		if derr != nil && strings.TrimSpace(out) == "" {
			continue // backend not present on this node; skip silently
		}
		appendRuleset(rb, strings.Join(argv, " "), node, out, derr)
	}
}

// windowsNodeDump appends one Windows node's felix logs (calico-node-windows,
// container "node") and its HNS dataplane state. The ruleset is read through
// kubectl exec into the HostProcess pod — the Windows node is a QEMU VM, so
// dockerExec (which targets kind's docker containers) can't reach it. Get-HnsPolicyList
// is the direct analogue of what the hns.go renderer produces (the ACL policysets
// a DIFF disagrees about); hnsdiag is the fallback when the HNS module isn't loaded.
func windowsNodeDump(ctx context.Context, c *cluster, node string, fb, rb *strings.Builder) {
	fmt.Fprintf(fb, "=== felix @ %s (windows) ===\n", node)
	pod := nodeCalicoPod(ctx, c, "k8s-app=calico-node-windows", node)
	if pod == "" {
		fmt.Fprintf(fb, "(no calico-node-windows pod found on %s)\n\n", node)
		return
	}
	appendPodLogs(ctx, c, fb, pod, "node", node)

	for _, argv := range [][]string{
		{"powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-HnsPolicyList | ConvertTo-Json -Depth 20"},
		{"hnsdiag", "list", "all"},
	} {
		out, derr := c.exec(ctx, "calico-system", pod, "node", argv...)
		if derr != nil && strings.TrimSpace(out) == "" {
			continue // cmdlet/tool not present; skip silently
		}
		appendRuleset(rb, strings.Join(argv, " "), node, out, derr)
	}
}

// nodeCalicoPod returns the name of the calico-node[-windows] pod scheduled on
// node (empty if none / lookup failed — the caller reports the gap).
func nodeCalicoPod(ctx context.Context, c *cluster, selector, node string) string {
	pod, _ := c.kubectl(ctx, nil, "get", "pods", "-n", "calico-system",
		"-l", selector, "--field-selector", "spec.nodeName="+node,
		"-o", "jsonpath={.items[0].metadata.name}")
	return strings.TrimSpace(pod)
}

// appendPodLogs tails a container's logs into b, plus the previous instance's
// logs if the pod restarted. If calico-node restarted (it crash-loops when e.g.
// typha is briefly unreachable), the *current* instance's logs are just the
// fresh boot sequence — the felix activity from when the policy was programmed
// is in the prior instance. kubectl --previous errors with an empty body when
// there's no prior instance, so we only append a real one.
func appendPodLogs(ctx context.Context, c *cluster, b *strings.Builder, pod, container, node string) {
	logs, lerr := c.kubectl(ctx, nil, "logs", "-n", "calico-system", pod,
		"-c", container, "--tail="+felixTail)
	if lerr != nil {
		fmt.Fprintf(b, "(logs %s failed: %v)\n", pod, lerr)
	}
	b.WriteString(logs)
	if !strings.HasSuffix(logs, "\n") {
		b.WriteByte('\n')
	}
	prev, pverr := c.kubectl(ctx, nil, "logs", "-n", "calico-system", pod,
		"-c", container, "--previous", "--tail="+felixTail)
	if pverr == nil && strings.TrimSpace(prev) != "" {
		fmt.Fprintf(b, "--- previous (pre-restart) instance @ %s ---\n", node)
		b.WriteString(prev)
		if !strings.HasSuffix(prev, "\n") {
			b.WriteByte('\n')
		}
	}
	b.WriteByte('\n')
}

// appendRuleset writes one dataplane-ruleset section (title @ node, exit note,
// body with a trailing blank line).
func appendRuleset(b *strings.Builder, title, node, out string, derr error) {
	fmt.Fprintf(b, "=== %s @ %s ===\n", title, node)
	if derr != nil {
		fmt.Fprintf(b, "(exit: %v)\n", derr)
	}
	b.WriteString(out)
	if !strings.HasSuffix(out, "\n") {
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
}
