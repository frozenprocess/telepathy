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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/frozenprocess/telepathy/api"
	"sigs.k8s.io/yaml"
)

// All tunables (env-backed knobs and the timing constants) live on the package's
// Config; see config.go. The harness reads them through the package-level cfg.

// TestE2E runs every applicable e2e/testdata case and fails if any assertion is
// wrong. By default it compares the engine against the live cluster's dataplane;
// with E2E_NO_CLUSTER=1 (the `make verify-all` backend) it skips the cluster and
// scores the engine's prediction against each case's authored `expect` instead.
// Both modes share the same case discovery, skip rules and engine invocation, so
// verify and e2e can't drift into two different answers.
func TestE2E(t *testing.T) {
	if cfg.NoCluster {
		checkProvider(t)
		runCases(t, "verify ("+cfg.Provider+")", func(t *testing.T, name, dir string) {
			verifyCase(t, name, dir)
		})
		return
	}
	c, err := newCluster()
	if err != nil {
		t.Fatalf("cluster not ready (did `make e2e` / hacks/provision/calico-up.sh run?): %v", err)
	}
	runCases(t, "e2e ("+cfg.Provider+")", func(t *testing.T, name, dir string) {
		runCase(t, c, name, dir)
	})
}

// runCases discovers every e2e/testdata case, runs each through `run` as a subtest,
// and logs a one-line pass/fail/skip tally at the end. `go test` prints per-case
// PASS/FAIL/SKIP lines and a single closing FAIL/ok, but no counts — and a failure
// can scroll far above the closing line, so the summary is easy to miss otherwise.
func runCases(t *testing.T, label string, run func(t *testing.T, name, dir string)) {
	entries, err := os.ReadDir(cfg.TestdataDir)
	if err != nil {
		t.Fatalf("read testdata dir %s: %v", cfg.TestdataDir, err)
	}

	// The subtests run sequentially (no t.Parallel), so appending here is race-free.
	var passed, failed, skipped int
	var failedNames, skippedNames []string

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(cfg.TestdataDir, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "assertions.yaml")); err != nil {
			continue // not a case directory
		}
		name := e.Name()
		// This filters cases via flavor, so the engine doesn't log skipping.
		if flavor := readFlavor(t, filepath.Join(dir, "meta.yaml")); flavor != "k8s" && flavor != cfg.Provider {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() {
				switch {
				case t.Failed():
					failed++
					failedNames = append(failedNames, name)
				case t.Skipped():
					skipped++
					skippedNames = append(skippedNames, name)
				default:
					passed++
				}
			})
			run(t, name, dir)
		})
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s summary: %d passed, %d failed, %d skipped of %d cases",
		label, passed, failed, skipped, passed+failed+skipped)
	if failed > 0 {
		fmt.Fprintf(&b, "\n  failed:  %s", strings.Join(failedNames, ", "))
	}
	if skipped > 0 {
		fmt.Fprintf(&b, "\n  skipped: %s", strings.Join(skippedNames, ", "))
	}
	t.Log("\n" + b.String())
}

// checkProvider fails the run once, up front, if cfg.Provider isn't a provider the
// engine knows. Without it a typo'd PROVIDER (e.g. "antera") surfaces as one cryptic
// "engine output not JSON" failure per case, the real reason buried in each. We probe
// by running the engine over a throwaway assertion: an unknown provider is rejected
// before evaluation, a known one proceeds (and "fails" the dummy assertion, ignored).
func checkProvider(t *testing.T) {
	assertFile := filepath.Join(t.TempDir(), "provider-probe.yaml")
	if err := os.WriteFile(assertFile, []byte("[{from: a, to: b, expect: allow}]"), 0o644); err != nil {
		t.Fatalf("write provider-probe assertion: %v", err)
	}
	cmd := exec.CommandContext(context.Background(), cfg.TelepathyBin,
		"test", "-provider", cfg.Provider, "-assert", assertFile)
	cmd.Stdin = strings.NewReader("")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run()
	if strings.Contains(stderr.String(), "unknown -provider") {
		t.Fatalf("%s", strings.TrimSpace(stderr.String()))
	}
}

// verifyCase is the engine-only path (E2E_NO_CLUSTER=1): it applies the same
// case-applicability rules runCase uses (flavor + the antrea engine's
// unsupported-kind gate) and runs the very same engine invocation, but scores the
// prediction against the case's authored `expect` instead of probing a cluster.
func verifyCase(t *testing.T, name, dir string) {
	provider := cfg.Provider
	// Flavor applicability is gated at enumeration (see runCases), so a case that
	// reaches here already applies to this provider.
	policyText := string(readFile(t, filepath.Join(dir, "policy.yaml")))
	if k8sOnlyProvider(provider) {
		if kind := unsupportedK8sOnlyKind(policyText); kind != "" {
			t.Skipf("%s engine does not evaluate %s — skipping (would misreport)", provider, kind)
		}
	}

	topoBytes := readFile(t, filepath.Join(dir, "topology.yaml"))
	assertions, err := api.DecodeAssertions(readFile(t, filepath.Join(dir, "assertions.yaml")))
	if err != nil {
		t.Fatalf("decode assertions: %v", err)
	}
	report, stderr, err := runEngine(context.Background(), string(topoBytes),
		filepath.Join(dir, "policy.yaml"), filepath.Join(dir, "assertions.yaml"))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if len(report.Results) != len(assertions) {
		t.Fatalf("engine returned %d results for %d assertions\nstderr: %s", len(report.Results), len(assertions), stderr)
	}
	for _, r := range report.Results {
		if r.Pass {
			continue
		}
		got := dash(r.Got)
		if r.Err != "" {
			got = "error: " + r.Err
		}
		t.Errorf("%s -> %s: expect %s, engine got %s", r.Assertion.From, r.Assertion.To, r.Assertion.Expect, got)
	}
}

// runCase orchestrates one e2e/testdata case end to end (see doc.go for the phases).
func runCase(t *testing.T, c *cluster, name, dir string) {
	ctx := context.Background()

	provider := cfg.Provider
	// Flavor applicability is gated at enumeration (see runCases); a case that
	// reaches here already applies to this provider.
	// requiresOS gates a case on the run's E2E_OS: a case whose topology pins a pod
	// to a Windows node can't schedule on a Linux-only cluster, so skip (don't fail)
	// unless the run targets that OS. Engine-only verify (NoCluster) is OS-agnostic
	// and never reaches here.
	if want := readMetaStr(t, filepath.Join(dir, "meta.yaml"), "requiresOS"); want != "" && want != cfg.OS {
		t.Skipf("case requires E2E_OS=%s, run is %s — skipping", want, cfg.OS)
	}
	avoidColocation := readMetaFlag(t, filepath.Join(dir, "meta.yaml"), "hepAvoidColocation")
	// externalProbe realizes `role: external` endpoints as off-cluster Docker
	// containers on the kind network (rather than pods) and probes from them via
	// `docker exec`. This is the only externally routable vantage, needed for
	// north-south cases (preDNAT/NodePort) where the policy is exercised by
	// traffic entering a node from outside. See doc.go / README.
	externalProbe := readMetaFlag(t, filepath.Join(dir, "meta.yaml"), "externalProbe")
	// costCheck validates the policy rules telepathy renders for this case against
	// the rules the cluster actually programs (opt-in per case via `cost: true` in
	// meta.yaml). Calico only; the dataplane read is OS-specific (iptables on
	// linux, HNS on windows). See validateCost.
	costCheck := cfg.Provider == "calico" && (cfg.OS == "linux" || cfg.OS == "windows") &&
		readMetaFlag(t, filepath.Join(dir, "meta.yaml"), "cost")

	topoBytes := readFile(t, filepath.Join(dir, "topology.yaml"))
	assertBytes := readFile(t, filepath.Join(dir, "assertions.yaml"))
	policyText := string(readFile(t, filepath.Join(dir, "policy.yaml")))

	// The Antrea and Cilium engines only predict upstream Kubernetes
	// NetworkPolicy; they do not yet evaluate the NPA admin tier
	// (ClusterNetworkPolicy / Admin- / BaselineAdminNetworkPolicy) or vendor
	// CRDs. A k8s-flavored case that leans on those kinds would have the
	// dataplane enforce them while the engine ignores them — a false DIFF, not a
	// real disagreement. Skip such cases for those providers (they light up
	// automatically once the engine grows that support).
	if k8sOnlyProvider(provider) {
		if kind := unsupportedK8sOnlyKind(policyText); kind != "" {
			t.Skipf("%s engine does not evaluate %s — skipping (would misreport)", provider, kind)
		}
	}

	req, err := api.DecodeRequest(topoBytes)
	if err != nil {
		t.Fatalf("decode topology: %v", err)
	}
	assertions, err := api.DecodeAssertions(assertBytes)
	if err != nil {
		t.Fatalf("decode assertions: %v", err)
	}

	// External endpoints (off-cluster observers) under externalProbe: realized as
	// Docker containers, not pods. Indexed by endpoint ID so the pod/namespace
	// phases can skip them and the probe phase can route their flows via docker.
	isExternal := func(e api.Endpoint) bool {
		return externalProbe && strings.EqualFold(e.Role, "external")
	}
	externalEP := map[string]bool{}
	for _, e := range req.Endpoints {
		if isExternal(e) {
			externalEP[e.ID] = true
		}
	}

	if len(req.HostEndpoints) > 0 && !cfg.IncludeHEP {
		t.Skipf("HostEndpoint case skipped (narrows Calico failsafes cluster-wide while it runs); set E2E_INCLUDE_HEP=1 to run")
	}

	nodeSet, err := c.nodes(ctx)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Some cases only reproduce on a cluster with enough nodes to spread work
	// across — e.g. a hepAvoidColocation HEP needs a worker that hosts none of
	// the pods it must police across the host boundary, which is impossible when
	// every pod shares the one available worker. On a too-small cluster the HEP
	// is forced to colocate and the dataplane can't enforce the policy, producing
	// a misleading engine-vs-cluster DIFF. `minNodes:` in meta.yaml declares the
	// floor; skip (don't fail) below it so the shortfall reads as "not exercised"
	// rather than a false positive.
	if min, ok := readMetaInt(t, filepath.Join(dir, "meta.yaml"), "minNodes"); ok && len(nodeSet) < min {
		t.Skipf("case needs >= %d nodes, cluster has %d — skipping (would colocate and misreport)", min, len(nodeSet))
	}

	// Place HostEndpoints off the control-plane where possible: an enforced host
	// policy must not be able to sever the API server / etcd that run there. Each
	// HEP gets a DISTINCT node (two hostNetwork stand-in pods on one node would
	// fight over the same agnhost ports), preferring workers and only falling
	// back to the control-plane when workers run out — so a 2-HEP/2-node case
	// keeps its authored one-per-node layout. We mutate req so the engine
	// evaluates the same placement (engineTopology re-marshals from req).
	hepRelocated := false
	if len(req.HostEndpoints) > 0 {
		cp, err := c.controlPlaneNodes(ctx)
		if err != nil {
			t.Fatalf("%v", err)
		}
		workers, err := c.workerNodes(ctx)
		if err != nil {
			t.Fatalf("%v", err)
		}
		used := map[string]bool{} // nodes already carrying a HEP
		for i := range req.HostEndpoints {
			if !cp[req.HostEndpoints[i].Node] {
				used[req.HostEndpoints[i].Node] = true // keep HEPs already on a worker
			}
		}
		// A "*"-interface HEP can't police traffic to/from a pod on its OWN node:
		// that traffic rides a cali workload interface, which host endpoints don't
		// select. So a host<->pod assertion only reproduces on the cluster when the
		// HEP and that pod sit on different nodes. When a case opts in via
		// `hepAvoidColocation: true` in meta.yaml, collect the nodes hosting pods
		// that appear opposite a host/ actor and steer relocation away from them.
		// Opt-in (not automatic) because it only matters for cases with host<->pod
		// assertions, and steering can shuffle placement for cases that don't care.
		// (Same-node host<->pod is a kind/dataplane limitation, not an engine
		// discrepancy — same spirit as the SNAT note in nodeSubnetPoolManifest.)
		avoidNode := map[string]bool{}
		if avoidColocation {
			nodeByEndpoint := map[string]string{}
			for _, e := range req.Endpoints {
				nodeByEndpoint[e.ID] = e.Node
			}
			for _, a := range assertions {
				fromHost := strings.HasPrefix(a.From, "host/")
				toHost := strings.HasPrefix(a.To, "host/")
				if fromHost == toHost {
					continue // both-host or neither-host: no host<->pod node constraint
				}
				podID := a.From
				if fromHost {
					podID = a.To
				}
				if n := nodeByEndpoint[podID]; n != "" {
					avoidNode[n] = true
				}
			}
		}
		freeWorker := func() string {
			for _, w := range workers { // prefer a worker not hosting a policed pod
				if !used[w] && !avoidNode[w] {
					return w
				}
			}
			for _, w := range workers { // fall back to any free worker
				if !used[w] {
					return w
				}
			}
			return ""
		}
		for i := range req.HostEndpoints {
			if !cp[req.HostEndpoints[i].Node] {
				continue // already on a worker
			}
			w := freeWorker()
			if w == "" {
				t.Logf("HostEndpoint %q stays on control-plane %q (no free worker: %d HEPs, %d workers)",
					req.HostEndpoints[i].Name, req.HostEndpoints[i].Node, len(req.HostEndpoints), len(workers))
				used[req.HostEndpoints[i].Node] = true
				continue
			}
			t.Logf("relocating HostEndpoint %q from control-plane %q to worker %q (keep host policy off the control-plane)",
				req.HostEndpoints[i].Name, req.HostEndpoints[i].Node, w)
			req.HostEndpoints[i].Node = w
			used[w] = true
			hepRelocated = true
		}
	}
	agnhostImg := cfg.AgnhostImage
	plan := serverPorts(req, assertions)

	// Host stand-in pods are only needed for HEPs that a probe actually
	// originates from or targets (a "host/<name>" actor in some assertion).
	// HEPs that exist solely to carry policy (e.g. a per-node forward firewall
	// with no host/ assertions) get the HostEndpoint resource but no pod —
	// avoiding pointless deploys and, crucially, the agnhost port clash two
	// hostNetwork pods would hit if forced onto the same node.
	referencedHosts := map[string]bool{}
	for _, a := range assertions {
		for _, id := range []string{a.From, a.To} {
			if name, ok := strings.CutPrefix(id, "host/"); ok {
				referencedHosts[name] = true
			}
		}
	}

	// Gate the scenario on a recovered control plane. A preceding HostEndpoint
	// case narrows Calico's failsafes cluster-wide and flushes conntrack on the
	// nodes; if its teardown returned while Felix was still reprogramming (or a
	// node briefly lost the apiserver), this case could probe through a cluster
	// whose own components are flapping — a false-positive DIFF unrelated to the
	// policy under test. ensureClusterHealthy waits for Calico to report healthy
	// and, if it doesn't, restarts the Calico components before giving up.
	ensureClusterHealthy(ctx, t, c, provider)

	// --- Phase 1: namespaces -------------------------------------------------
	createdNS := map[string]bool{}
	ensure := func(ns string, labels map[string]string) {
		created, err := c.ensureNamespace(ctx, ns, labels)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if created {
			createdNS[ns] = true
		}
	}
	nsLabels := map[string]map[string]string{}
	for _, n := range req.Namespaces {
		nsLabels[n.Name] = n.Labels
	}
	for _, e := range req.Endpoints {
		if isExternal(e) {
			continue // off-cluster observer: no pod, so no namespace to create
		}
		if _, ok := nsLabels[e.Namespace]; !ok {
			nsLabels[e.Namespace] = nil
		}
	}
	// Pre-clean: a target namespace that already exists at case start is an
	// orphan from a previous run that didn't tear down — interrupted with Ctrl-C,
	// killed by a timeout, or a second `go test` overlapping the first. Its
	// leftover pods are pinned to whatever nodes that run chose, and `kubectl
	// apply` can't relocate a pod to this case's pins (nodeName is immutable), so
	// the base-resource apply below would fail every time. Delete such namespaces
	// and wait for them to drain (deleteNamespace blocks on Terminating too, which
	// also resolves the race against a prior case still tearing down) so each case
	// starts from a clean slate regardless of how the previous run ended.
	targets := make([]string, 0, len(nsLabels)+1)
	for ns := range nsLabels {
		targets = append(targets, ns)
	}
	if len(referencedHosts) > 0 {
		targets = append(targets, hostNS)
	}
	for _, ns := range targets {
		// Never pre-clean a system namespace: it isn't a harness orphan, it's part
		// of the cluster, and deleting kube-system (or calico-system, etc.) would
		// take the cluster down. A case that names one is relabelled additively by
		// ensureNamespace and left otherwise untouched — see protectedNamespace and
		// the create+label note in ensureNamespace. (A case must not deploy its own
		// pods into a system namespace; cases model system services like DNS in a
		// managed stand-in namespace excluded from policy instead.)
		if protectedNamespace(ns) {
			continue
		}
		if _, err := c.kubectl(ctx, nil, "get", "ns", ns); err == nil {
			t.Logf("pre-clean: namespace %q left over from a previous run — deleting before reuse", ns)
			if err := c.deleteNamespace(ctx, ns); err != nil {
				t.Fatalf("pre-clean delete orphan ns %s: %v", ns, err)
			}
		}
	}
	// Cluster-scoped policy objects (GlobalNetworkPolicy/Set, HostEndpoint) outlive
	// namespace deletion, so a leftover from a prior run keeps applying to this case
	// — a default-tier deny-all from another case, for instance, silently denies
	// traffic the engine predicts as allowed. Clear non-operator leftovers before
	// applying this case's own policy.
	if out, err := c.deleteOrphanClusterPolicies(ctx); err != nil {
		t.Logf("pre-clean delete orphan cluster policies: %v\n%s", err, out)
	}
	for ns, labels := range nsLabels {
		ensure(ns, labels)
	}
	if len(referencedHosts) > 0 {
		ensure(hostNS, nil)
	}

	// --- Phase 2: base resources (SAs, pods, host pods, services) ------------
	var docs []string
	for _, sa := range neededServiceAccounts(req) {
		docs = append(docs, serviceAccountManifest(sa))
	}
	// Pods carry the node OS in their name (e.g. frontend-windows) so `kubectl get
	// pods` shows placement at a glance. The suffix is a cluster-object-name detail
	// only — endpoint IDs (the engine's and assertions' keys) are untouched — so we
	// track ID -> actual pod name and use it wherever a pod is addressed by name.
	podNameByID := map[string]string{}
	osByID := map[string]string{} // endpoint ID -> node OS, for the report labels
	// An ICMP probe needs a ping client on the sender; the Windows agnhost image
	// has none. So any endpoint used as the source of an ICMP flow is always pinned
	// to a Linux node (with the Linux agnhost image), regardless of E2E_OS — the
	// receiver's OS is unconstrained, since its stack answers echo natively. This is
	// what lets Windows-receiver ICMP cases run: Linux sender -> Windows HNS ingress.
	icmpSrc := map[string]bool{}
	for _, a := range assertions {
		if p := effProto(a, req); p == "icmp" || p == "icmpv6" {
			icmpSrc[a.From] = true
		}
	}
	for _, ep := range req.Endpoints { // ep is a copy; mutating it won't touch req
		if externalEP[ep.ID] {
			continue // off-cluster observer: a Docker container, not a pod (launched below)
		}
		// Pin the pod to a node of the configured OS (E2E_OS, default linux) so the
		// policy is enforced by that OS's dataplane — Windows/HNS under E2E_OS=windows.
		// A per-endpoint nodeSelector (topology) is the author's explicit intent and
		// takes precedence.
		if len(ep.NodeSelector) == 0 {
			ep.NodeSelector = map[string]string{"kubernetes.io/os": cfg.OS}
		}
		osName := ep.NodeSelector["kubernetes.io/os"]
		if osName == "" {
			osName = cfg.OS // per-endpoint selector without an os key
		}
		// ICMP sources override everything onto Linux so they have ping (see above).
		// The agnhost ref is a multi-arch manifest, so the Linux node pulls the
		// Linux layer (with busybox ping) automatically — no separate image needed.
		if icmpSrc[ep.ID] {
			osName = "linux"
			ep.NodeSelector = map[string]string{"kubernetes.io/os": "linux"}
		}
		// Every testdata `node:` pin names a Linux node (control-plane/worker). On a
		// non-Linux OS that pin becomes a `nodeName`, which OVERRIDES the OS
		// nodeSelector and strands the pod back on Linux — defeating the Windows run.
		// Drop the pin so the nodeSelector places the pod on the target-OS node (with
		// a single Windows node, all pods co-locate there — same-node enforcement
		// only; no cross-node distribution). ep is a copy, so the engine still sees
		// the original node: (it doesn't branch on Node for non-HEP cases anyway).
		if osName != "linux" {
			ep.Node = ""
		}
		ep.Name += "-" + osName
		podNameByID[ep.ID] = ep.Name
		osByID[ep.ID] = osName
		docs = append(docs, podManifest(ep, plan, nodeSet, agnhostImg))
	}
	for _, h := range req.HostEndpoints {
		if referencedHosts[h.Name] {
			docs = append(docs, hostPodManifest(h.Name, h.Node, plan, agnhostImg))
		}
	}
	for _, s := range req.Services {
		docs = append(docs, serviceManifest(s))
	}
	baseManifest := joinManifests(docs...)

	// External observers: one Docker container per role:external endpoint, on the
	// kind network, harvested for its IP. Probes from these run via docker exec;
	// the IP feeds the rewriter below so the engine evaluates the same real source.
	extContainer := map[string]string{} // endpoint ID -> container name
	extIP := map[string]string{}        // endpoint ID -> observer IP on the kind net
	if len(externalEP) > 0 {
		anyNode := ""
		for n := range nodeSet {
			if anyNode == "" || n < anyNode {
				anyNode = n
			}
		}
		network, err := c.nodeNetwork(ctx, anyNode)
		if err != nil {
			t.Fatalf("discover kind network: %v", err)
		}
		for _, ep := range req.Endpoints {
			if externalEP[ep.ID] {
				extContainer[ep.ID] = "telepathy-ext-" + sanitizeName(ep.ID)
			}
		}
		t.Cleanup(func() {
			if cfg.KeepOnFailure && t.Failed() {
				t.Logf("E2E_KEEP=1: leaving observer container(s) %s for inspection (docker rm -f to clean up)",
					strings.Join(sortedValues(extContainer), ", "))
				return
			}
			for _, cname := range extContainer {
				c.removeObserver(context.Background(), cname)
			}
		})
		for _, ep := range req.Endpoints {
			if !externalEP[ep.ID] {
				continue
			}
			ip, err := c.startObserver(ctx, extContainer[ep.ID], network, agnhostImg)
			if err != nil {
				t.Fatalf("start external observer for %s: %v", ep.ID, err)
			}
			extIP[ep.ID] = ip
			t.Logf("external observer %s -> container %s @ %s (network %s)", ep.ID, extContainer[ep.ID], ip, network)
		}
	}

	// Manifests captured by the cleanup closure (by reference) — assigned as
	// each is rendered/applied below, so a mid-apply failure still tears down
	// whatever already landed.
	var appliedPolicy, appliedHEP, appliedNetset, appliedNodePool string
	// Engine-side outputs, hoisted so the failure-diagnostics cleanup below can
	// read them by reference. They stay zero-valued until their phase runs, so a
	// t.Fatalf at any earlier phase still produces a (partial) dump.
	var (
		rewrittenTopo string
		engineStderr  string
		report        api.AssertionReport
		rep           *caseReport
	)
	hepNodes := hepNodeList(req)
	t.Cleanup(func() {
		cctx := context.Background()
		// E2E_KEEP: freeze a failed case's scene for live inspection. We skip the
		// whole teardown — including the failsafe restore for HEP cases — so what
		// kubectl shows is exactly what the probe saw. The narrowed failsafes keep
		// apiserver/etcd/kubelet open, so the cluster stays reachable; the message
		// says how to undo it. Only on failure: green cases always clean up.
		if cfg.KeepOnFailure && t.Failed() {
			msg := fmt.Sprintf("E2E_KEEP=1: leaving case %q in place for inspection (namespaces: %s); "+
				"clean up with hacks/provision/calico-down.sh", name, strings.Join(sortedKeys(createdNS), ", "))
			if len(hepNodes) > 0 {
				msg += " (NOTE: this HEP case left Calico failsafes narrowed cluster-wide; " +
					"restore them by re-running teardown or `hacks/provision/calico-down.sh`)"
			}
			t.Log(msg)
			return
		}
		// Policy teardown is two passes because Calico rejects deleting a
		// non-empty tier synchronously (admission webhook), so the tier's GNPs
		// must be *gone* — not just delete-requested — before the tier delete is
		// issued. Pass 1 waits (no --wait=false) so the GNPs finalize; its own
		// tier delete fails (tier still non-empty at that instant) and is
		// ignored. Pass 2 deletes the now-empty tier. We only ever delete the
		// case manifest's own objects, so the built-in tiers (default,
		// kube-admin, kube-baseline) — which can't be deleted by design — are
		// never touched. Then HEPs, restore failsafes, then netsets.
		if appliedPolicy != "" {
			_, _ = c.kubectl(cctx, []byte(appliedPolicy), "delete", "--ignore-not-found", "-f", "-")
			if out, err := c.deleteManifest(cctx, appliedPolicy); err != nil {
				t.Logf("teardown delete policy: %v\n%s", err, out)
			}
		}
		if appliedHEP != "" {
			_, _ = c.deleteManifest(cctx, appliedHEP)
		}
		if len(hepNodes) > 0 {
			if err := setFailsafes(cctx, c, false); err != nil {
				t.Logf("teardown restore failsafes: %v", err)
			}
			flushConntrack(cctx, c, hepNodes)
		}
		if appliedNodePool != "" {
			if out, err := c.deleteManifest(cctx, appliedNodePool); err != nil {
				t.Logf("teardown delete node-subnet IPPool: %v\n%s", err, out)
			}
		}
		if appliedNetset != "" {
			_, _ = c.deleteManifest(cctx, appliedNetset)
		}
		for ns := range createdNS {
			if err := c.deleteNamespace(cctx, ns); err != nil {
				t.Logf("teardown delete ns %s: %v", ns, err)
			}
		}
	})

	// Failure diagnostics. Registered AFTER the teardown closure so LIFO runs it
	// FIRST — while the case is still live — and registered HERE, before the
	// apply/wait/engine/probe phases below, so a t.Fatalf at ANY of them still
	// triggers the dump (the engine vars it reads are hoisted above and simply
	// stay empty for phases that didn't run). No-ops unless the case failed.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		caseNamespaces := sortedKeys(createdNS)
		if len(referencedHosts) > 0 {
			caseNamespaces = append(caseNamespaces, hostNS)
		}
		collectDiagnostics(context.Background(), t, c, diagInputs{
			name:          name,
			appliedPolicy: appliedPolicy,
			engineTopo:    rewrittenTopo,
			engineReport:  report,
			engineStderr:  engineStderr,
			rep:           rep,
			namespaces:    caseNamespaces,
		})
	})

	// Pods in a protected namespace (e.g. default) survive the namespace-delete
	// pre-clean — the harness never deletes those namespaces — so a leftover from
	// a prior run whose spec has since changed makes `apply` try to patch a pod's
	// immutable fields (command/ports) and fail. Non-protected namespaces were
	// already wiped wholesale above, so only protected ones can still hold a
	// colliding pod. Delete this case's own pods there by name first, so apply
	// creates them fresh — the same clean slate every other namespace gets.
	for _, ep := range req.Endpoints {
		if externalEP[ep.ID] || !protectedNamespace(ep.Namespace) {
			continue
		}
		if name := podNameByID[ep.ID]; name != "" {
			if out, err := c.kubectl(ctx, nil, "delete", "pod", "-n", ep.Namespace, name,
				"--ignore-not-found", "--wait=true", "--timeout=120s"); err != nil {
				t.Fatalf("pre-apply delete stale pod %s/%s: %v\n%s", ep.Namespace, name, err, out)
			}
		}
	}

	// Cost baseline: the policy-rule count BEFORE this case's policy lands, so the
	// post-convergence delta isolates exactly this case's policy rules (cases run
	// sequentially and tear down cleanly, so nothing else moves it). If the
	// dataplane isn't readable (wrong backend / no Windows node) skip rather than
	// miscount. See e2e/cost.go.
	var costBaseline policyRuleCounts
	if costCheck {
		var berr error
		if costBaseline, berr = c.policyRuleCounts(ctx); berr != nil {
			t.Fatalf("cost baseline: %v", berr)
		}
		if !costBaseline.linuxPresent && !costBaseline.nftPresent && !costBaseline.hnsPresent && !costBaseline.bpfPresent {
			t.Logf("cost: no readable dataplane (wrong backend / no node) — skipping cost validation")
			costCheck = false
		}
	}

	if out, err := c.apply(ctx, baseManifest); err != nil {
		t.Fatalf("apply base resources: %v\n%s", err, out)
	}

	// --- Phase 3: wait Ready, harvest real IPs -------------------------------
	for ns := range createdNS {
		if out, err := c.waitPodsReady(ctx, ns, 2*time.Minute); err != nil {
			t.Fatalf("wait pods ready in %s: %v\n%s", ns, err, out)
		}
	}
	if len(referencedHosts) > 0 {
		if out, err := c.waitPodsReady(ctx, hostNS, 2*time.Minute); err != nil {
			t.Fatalf("wait host pods ready: %v\n%s", err, out)
		}
	}
	// Pods (re)created in a protected namespace aren't covered by the createdNS
	// wait above (the harness doesn't own those namespaces, so they aren't in the
	// set). Wait for them by name — not `pod --all`, which would also block on any
	// unrelated pod living in that shared namespace — before harvesting their IPs.
	for _, ep := range req.Endpoints {
		if externalEP[ep.ID] || !protectedNamespace(ep.Namespace) {
			continue
		}
		if name := podNameByID[ep.ID]; name != "" {
			if out, err := c.kubectl(ctx, nil, "wait", "-n", ep.Namespace,
				"--for=condition=Ready", "pod", name, "--timeout=120s"); err != nil {
				t.Fatalf("wait pod ready %s/%s: %v\n%s", ep.Namespace, name, err, out)
			}
		}
	}

	podIPByID := map[string]string{}
	for _, ep := range req.Endpoints {
		if externalEP[ep.ID] {
			// Off-cluster observer: its "real IP" is the Docker container's address,
			// harvested above. Feeding it here lets buildIPRewriter map the endpoint's
			// fictional IP (and any policy CIDR containing it) to the observer's IP,
			// so the engine matches the same source the dataplane sees.
			podIPByID[ep.ID] = extIP[ep.ID]
			continue
		}
		ip, err := c.podIP(ctx, ep.Namespace, podNameByID[ep.ID]) // OS-suffixed pod name
		if err != nil || ip == "" {
			t.Fatalf("pod IP for %s: %v", ep.ID, err)
		}
		podIPByID[ep.ID] = ip
	}
	nodeIP := map[string]string{}
	hostIPByName := map[string]string{}
	for _, h := range req.HostEndpoints {
		ip, err := c.nodeInternalIP(ctx, h.Node)
		if err != nil || ip == "" {
			t.Fatalf("node InternalIP for %s: %v", h.Node, err)
		}
		nodeIP[h.Node] = ip
		hostIPByName[h.Name] = ip
	}
	svcIP := map[string]string{}
	svcNodePort := map[string]int{} // svc/<ns>/<name> -> allocated NodePort (NodePort services only)
	for _, s := range req.Services {
		ip, err := c.serviceClusterIP(ctx, s.Namespace, s.Name)
		if err != nil || ip == "" {
			t.Fatalf("service ClusterIP for %s/%s: %v", s.Namespace, s.Name, err)
		}
		svcIP["svc/"+s.Namespace+"/"+s.Name] = ip
		if strings.EqualFold(s.Type, "NodePort") {
			np, err := c.serviceNodePort(ctx, s.Namespace, s.Name)
			if err != nil || np == 0 {
				t.Fatalf("service NodePort for %s/%s: %v", s.Namespace, s.Name, err)
			}
			svcNodePort["svc/"+s.Namespace+"/"+s.Name] = np
		}
	}

	// probeNodeIP is the node address an external observer dials for a NodePort
	// target (a NodePort is reachable on every node; we pick one deterministically,
	// preferring a HEP-bearing node so the preDNAT host firewall under test is in
	// the path).
	probeNodeIP := ""
	if externalProbe && len(svcNodePort) > 0 {
		best := "" // smallest HEP node name, for determinism
		for n := range nodeIP {
			if best == "" || n < best {
				best = n
			}
		}
		if best != "" {
			probeNodeIP = nodeIP[best]
		}
		if probeNodeIP == "" { // no HEP nodes — fall back to any cluster node
			best = ""
			for n := range nodeSet {
				if best == "" || n < best {
					best = n
				}
			}
			if best != "" {
				if ip, err := c.nodeInternalIP(ctx, best); err == nil {
					probeNodeIP = ip
				}
			}
		}
		if probeNodeIP == "" {
			t.Fatalf("externalProbe: no node IP available to target NodePort services")
		}
	}

	rw := buildIPRewriter(req, podIPByID, nodeIP)
	for _, w := range rw.warns {
		t.Logf("warning: %s", w)
	}

	// --- Phase 4: apply netsets, HEPs, policy (all IP-remapped) --------------
	var netsetDocs []string
	for _, n := range req.NetworkSets {
		n.Nets = rw.rewriteNets(n.Nets)
		netsetDocs = append(netsetDocs, networkSetManifest(n))
	}
	for _, n := range req.GlobalNetworkSets {
		n.Nets = rw.rewriteNets(n.Nets)
		netsetDocs = append(netsetDocs, globalNetworkSetManifest(n))
	}
	if len(netsetDocs) > 0 {
		appliedNetset = joinManifests(netsetDocs...)
		if out, err := c.apply(ctx, appliedNetset); err != nil {
			t.Fatalf("apply netsets: %v\n%s", err, out)
		}
	}

	if len(req.HostEndpoints) > 0 {
		if err := setFailsafes(ctx, c, true); err != nil {
			t.Fatalf("%v", err)
		}
		// Stop natOutgoing from SNATing pod->node-IP traffic, which would hide a
		// source pod's labels from the HostEndpoint and make its ingress policy
		// unmatchable on the cluster (a dataplane-only divergence, not an engine
		// one). A disabled IPPool over the node subnet keeps the real pod source
		// IP. See nodeSubnetPoolManifest. Opt out with E2E_NO_NODE_POOL=1 (used to
		// isolate the pool's effect when diagnosing a case).
		if !cfg.NoNodePool {
			cidr, err := nodeSubnetCIDR(nodeIP[req.HostEndpoints[0].Node])
			if err != nil {
				t.Fatalf("derive node subnet CIDR: %v", err)
			}
			appliedNodePool = nodeSubnetPoolManifest(cidr)
			if out, err := c.apply(ctx, appliedNodePool); err != nil {
				t.Fatalf("apply node-subnet IPPool: %v\n%s", err, out)
			}
		}
		var hepDocs []string
		for _, h := range req.HostEndpoints {
			h.ExpectedIPs = []string{nodeIP[h.Node]}
			hepDocs = append(hepDocs, hostEndpointManifest(h))
		}
		appliedHEP = joinManifests(hepDocs...)
		if out, err := c.apply(ctx, appliedHEP); err != nil {
			t.Fatalf("apply host endpoints: %v\n%s", err, out)
		}
		flushConntrack(ctx, c, hepNodes)
	}

	appliedPolicy = rw.rewriteText(policyText)
	if out, err := c.apply(ctx, appliedPolicy); err != nil {
		t.Fatalf("apply policy: %v\n%s", err, out)
	}
	// HostEndpoint policy (especially applyOnForward + preDNAT, which program the
	// host forward / mangle-PREROUTING chains) converges noticeably slower than
	// workload policy — on a freshly provisioned cluster with HEPs, failsafes and
	// an IPPool all churning at once, a preDNAT DROP rule was observed taking well
	// over 20s to land. Because a probe records "allow" on its first success, a
	// deny flow probed before convergence is a false allow — so give HEP cases a
	// generous settle.
	settle := cfg.SettleDelay
	if len(req.HostEndpoints) > 0 {
		settle = cfg.HEPSettleDelay
	}
	time.Sleep(settle)

	// --- Phase 5: engine prediction over the rewritten topology --------------
	rewrittenTopo, err = engineTopology(req, topoBytes, rw, hepRelocated)
	if err != nil {
		t.Fatalf("build engine topology: %v", err)
	}
	rewrittenPolicyFile := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(rewrittenPolicyFile, []byte(appliedPolicy), 0o644); err != nil {
		t.Fatalf("write rewritten policy: %v", err)
	}
	report, engineStderr, err = runEngine(ctx, rewrittenTopo, rewrittenPolicyFile, filepath.Join(dir, "assertions.yaml"))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if len(report.Results) != len(assertions) {
		t.Fatalf("engine returned %d results for %d assertions\nstderr: %s", len(report.Results), len(assertions), engineStderr)
	}

	// --- Phase 6: probe the cluster and compare ------------------------------
	// Clear conntrack on the HEP nodes one more time so the first probe evaluates
	// against the now-converged policy, never riding an ESTABLISHED entry that
	// predates the deny (which would read as a false allow).
	if len(hepNodes) > 0 {
		flushConntrack(ctx, c, hepNodes)
	}
	quarantine := loadQuarantine(t, dir)
	rep = &caseReport{name: name}

	// probeAssertion runs one assertion end to end and returns its row. It only
	// reads the (now-immutable) topology maps and shells out via probe(), so many
	// can run at once — see the fan-out below.
	probeAssertion := func(i int, a api.Assertion) row {
		port := effPort(a, req)
		proto := effProto(a, req)
		// Decorate workload actors with their node OS (e.g. prod/frontend[windows])
		// so the report shows where each pod ran; host/external/service ids have no OS.
		rw := row{from: withOS(a.From, osByID), to: withOS(a.To, osByID), port: port, proto: proto, expect: a.Expect, engine: report.Results[i].Got}

		// Flows the environment can't faithfully reproduce (e.g. pod->node-IP
		// SNAT hiding the source identity) are recorded but not probed or
		// scored — see quarantine.yaml in the case dir.
		if reason, ok := quarantine[a.From+"->"+a.To]; ok {
			rw.quarantined = reason
			return rw
		}

		var src probeSource
		var serr string
		if externalEP[a.From] {
			src = probeSource{external: true, container: extContainer[a.From]}
		} else {
			src, serr = resolveSource(a.From, podNameByID)
		}
		dstIP, derr := resolveTargetIP(a.To, podIPByID, hostIPByName, svcIP)
		// External observers can't reach a ClusterIP or pod IP — only a node IP /
		// NodePort. When an external source targets a NodePort Service, dial the
		// node address on the allocated NodePort instead (the pre-DNAT path the
		// preDNAT host policy governs).
		if src.external && svcNodePort[a.To] != 0 {
			dstIP, derr = probeNodeIP, ""
			port = svcNodePort[a.To]
		}
		if serr != "" || derr != "" {
			rw.probeErr = strings.TrimSpace(serr + " " + derr)
			return rw
		}
		verdict, out, perr := probe(ctx, c, src, probeTarget{ip: dstIP, port: port}, proto)
		rw.clusterOut = out
		if perr != nil {
			rw.probeErr = perr.Error()
		} else {
			rw.cluster = verdict
		}
		return rw
	}

	// HEP and external-observer cases probe serially: their pre-loop conntrack
	// flush and NodePort routing assume one flow in flight at a time. Every other
	// case fans its independent per-assertion probes out across a bounded pool,
	// since a probe is almost entirely wait — an all-deny case (30 flows × 4 ×
	// agnhost --timeout=2s) is ~5min serial, enough to trip `go test -timeout`.
	workers := cfg.ProbeConcurrency
	if externalProbe || len(hepNodes) > 0 || workers < 1 {
		workers = 1
	}
	rows := make([]row, len(assertions))
	if workers == 1 {
		for i, a := range assertions {
			rows[i] = probeAssertion(i, a)
		}
	} else {
		var wg sync.WaitGroup
		sem := make(chan struct{}, workers)
		for i, a := range assertions {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, a api.Assertion) {
				defer wg.Done()
				defer func() { <-sem }()
				rows[i] = probeAssertion(i, a)
			}(i, a)
		}
		wg.Wait()
	}
	for _, rw := range rows {
		rep.add(rw)
	}

	t.Log("\n" + rep.render())
	if n := rep.mismatches(); n > 0 {
		t.Errorf("%d/%d assertions: engine disagrees with the cluster (or probe errored)", n, len(assertions))
	}

	// Cost validation runs last, after Felix has converged (post-settle,
	// post-probe): does the offline-rendered dataplane weight match what Calico
	// actually programmed for this case?
	if costCheck {
		validateCost(ctx, t, c, costBaseline, rewrittenTopo, rewrittenPolicyFile, osByID)
	}
}

// ensureClusterHealthy blocks until Calico reports every component healthy, so a
// scenario never runs on a control plane still recovering from the previous case
// (notably a HostEndpoint case, which narrows failsafes cluster-wide and flushes
// conntrack). On the happy path tigerastatus is already Available and this
// returns within a few seconds. Otherwise it restarts the Calico components and
// rechecks; if the cluster is still unhealthy it fails the case loudly — an
// honest infrastructure failure is preferable to a false-positive DIFF caused by
// the cluster's own plumbing being down. No-op for non-calico providers, which
// have no tigerastatus resource.
func ensureClusterHealthy(ctx context.Context, t *testing.T, c *cluster, provider string) {
	if provider != "calico" {
		return
	}
	if _, err := c.waitTigeraAvailable(ctx, cfg.HealthGrace); err == nil {
		return // common path: components already Available, returns near-instantly
	}
	t.Logf("Calico not Available within %s — rolling calico-node and rechecking", cfg.HealthGrace)
	if out, err := c.restartCalicoNode(ctx, cfg.HealthRestartTimeout); err != nil {
		// A rollout that doesn't converge is logged but not fatal here: the
		// recheck below is the real gate on whether the cluster is usable.
		t.Logf("calico-node restart did not fully converge: %v\n%s", err, out)
	}
	if out, err := c.waitTigeraAvailable(ctx, cfg.HealthRestartTimeout); err != nil {
		t.Fatalf("cluster still unhealthy after Calico restart (tigerastatus not Available) — "+
			"refusing to run case on a broken control plane: %v\n%s", err, out)
	}
	t.Logf("Calico recovered: all tigerastatus components Available")
}

// withOS decorates a workload actor id with its node OS for the report (e.g.
// "prod/frontend[windows]"). Non-workload actors (host/external/service) aren't
// in osByID and are returned unchanged.
func withOS(id string, osByID map[string]string) string {
	if os := osByID[id]; os != "" {
		return id + "[" + os + "]"
	}
	return id
}

// resolveSource maps an assertion's `from` id to the pod that originates the
// probe. A "host/<name>" source is the hostNetwork pod standing in for the HEP.
func resolveSource(id string, podNameByID map[string]string) (probeSource, string) {
	if rest, ok := strings.CutPrefix(id, "host/"); ok {
		return probeSource{ns: hostNS, pod: rest}, "" // HEP host pods aren't OS-suffixed
	}
	ns, _, ok := strings.Cut(id, "/")
	if !ok {
		return probeSource{}, fmt.Sprintf("bad source id %q", id)
	}
	// Use the realized pod name (endpoint name + OS suffix), not the raw id.
	name := podNameByID[id]
	if name == "" {
		return probeSource{}, fmt.Sprintf("no realized pod for source %q", id)
	}
	return probeSource{ns: ns, pod: name}, ""
}

// resolveTargetIP maps an assertion's `to` id to the IP to probe: a Service
// ClusterIP, a HEP's node IP, or a workload pod IP.
func resolveTargetIP(id string, podIP, hostIP, svcIP map[string]string) (string, string) {
	switch {
	case strings.HasPrefix(id, "svc/"):
		if ip := svcIP[id]; ip != "" {
			return ip, ""
		}
		return "", fmt.Sprintf("no ClusterIP for %q", id)
	case strings.HasPrefix(id, "host/"):
		if ip := hostIP[strings.TrimPrefix(id, "host/")]; ip != "" {
			return ip, ""
		}
		return "", fmt.Sprintf("no node IP for %q", id)
	default:
		if ip := podIP[id]; ip != "" {
			return ip, ""
		}
		return "", fmt.Sprintf("no pod IP for %q", id)
	}
}

// neededServiceAccounts returns the SAs to create: every declared one, plus a
// bare SA for any endpoint that names an SA not otherwise declared (so Calico's
// pcsa label projection has an object to read).
func neededServiceAccounts(req api.Request) []api.ServiceAccountInput {
	seen := map[string]bool{}
	var out []api.ServiceAccountInput
	for _, sa := range req.ServiceAccounts {
		out = append(out, sa)
		seen[sa.Namespace+"/"+sa.Name] = true
	}
	for _, e := range req.Endpoints {
		if e.ServiceAccountName == "" {
			continue
		}
		key := e.Namespace + "/" + e.ServiceAccountName
		if !seen[key] {
			seen[key] = true
			out = append(out, api.ServiceAccountInput{Name: e.ServiceAccountName, Namespace: e.Namespace})
		}
	}
	return out
}

func hepNodeList(req api.Request) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range req.HostEndpoints {
		if h.Node != "" && !seen[h.Node] {
			seen[h.Node] = true
			out = append(out, h.Node)
		}
	}
	return out
}

// runEngine runs `telepathy test -json` over the rewritten topology and decodes
// the AssertionReport. A non-zero exit just means some assertion failed against
// its authored `expect` — the JSON is still emitted and is what we want — so
// only a decode failure is treated as an error.
func runEngine(ctx context.Context, topologyText, policyFile, assertFile string) (api.AssertionReport, string, error) {
	cmd := exec.CommandContext(ctx, cfg.TelepathyBin,
		"test", "-provider", cfg.Provider, "-json", "-assert", assertFile, "-policy", policyFile)
	cmd.Stdin = strings.NewReader(topologyText)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	var rep api.AssertionReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		return rep, stderr.String(), fmt.Errorf("engine output not JSON (exit %v): %v\nstderr: %s", runErr, err, stderr.String())
	}
	return rep, stderr.String(), nil
}

func effPort(a api.Assertion, req api.Request) int {
	// ICMP carries no L4 port; never inherit the topology/default 8080 for it
	// (the probe ignores port for ICMP, and a phantom 8080 only misleads the report).
	if p := effProto(a, req); p == "icmp" || p == "icmpv6" {
		return 0
	}
	if a.Port != 0 {
		return a.Port
	}
	if req.Port != 0 {
		return req.Port
	}
	return 8080
}

func effProto(a api.Assertion, req api.Request) string {
	if a.Protocol != "" {
		return strings.ToLower(a.Protocol)
	}
	if req.Protocol != "" {
		return strings.ToLower(req.Protocol)
	}
	return "tcp"
}

func readFlavor(t *testing.T, path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "" // no meta => treated as not-applicable, skipped
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "flavor:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// readMetaStr reads a string-valued key from meta.yaml, returning "" when the
// key or file is absent. Used for gates like requiresOS.
func readMetaStr(t *testing.T, path, key string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, key+":"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// readMetaFlag reports whether meta.yaml sets the given key to a truthy value
// (true/1/yes). A missing key, a falsey value, or a missing file all yield
// false. Used to opt a case in to behaviour that shouldn't apply suite-wide —
// currently hepAvoidColocation (steer HostEndpoint relocation off the nodes
// hosting the pods the HEP must police across the host boundary).
func readMetaFlag(t *testing.T, path, key string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, key+":"); ok {
			switch strings.ToLower(strings.TrimSpace(rest)) {
			case "true", "1", "yes":
				return true
			}
			return false
		}
	}
	return false
}

// readMetaInt reads an integer-valued key from meta.yaml. It returns (value,
// true) when the key is present and parses as an int, and (0, false) when the
// key, the file, or a valid integer is absent. Used for numeric gates such as
// minNodes (the minimum cluster node count a case needs to reproduce).
func readMetaInt(t *testing.T, path, key string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, key+":"); ok {
			v, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				t.Fatalf("meta.yaml %s: %q is not an integer: %v", key, strings.TrimSpace(rest), err)
			}
			return v, true
		}
	}
	return 0, false
}

// k8sOnlyProvider reports whether an engine only predicts upstream Kubernetes
// NetworkPolicy (no Calico/Antrea/Cilium CRDs, no NPA admin tier). Both the
// Antrea and Cilium engines are in this class today, so k8s-flavored cases that
// lean on CRD kinds must be skipped for them (see unsupportedK8sOnlyKind).
func k8sOnlyProvider(provider string) bool {
	return provider == "antrea" || provider == "cilium"
}

// unsupportedK8sOnlyKind returns the first policy kind a k8s-NetworkPolicy-only
// engine (Antrea, Cilium) cannot evaluate, or "" if the manifest is plain k8s
// NetworkPolicy. Such a case would have the dataplane enforce the kind while the
// engine ignores it — a false DIFF, not a real disagreement. It is a
// deliberately shallow scan of `kind:` lines — enough to gate e2e case
// applicability without parsing the documents.
func unsupportedK8sOnlyKind(policyText string) string {
	unsupported := []string{"ClusterNetworkPolicy", "AdminNetworkPolicy", "BaselineAdminNetworkPolicy"}
	for _, line := range strings.Split(policyText, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "kind:")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		for _, u := range unsupported {
			if rest == u {
				return u
			}
		}
	}
	return ""
}

func readFile(t *testing.T, path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// engineTopology produces the topology fed to the engine, IP-remapped to the
// real pod/node IPs. Normally it rewrites the original topology.yaml text so the
// engine sees exactly what the file declares. When HostEndpoints were relocated
// to a worker node (hepRelocated), the original text no longer matches the
// cluster, so we re-marshal the mutated Request to YAML instead — keeping the
// engine and the dataplane on identical node placement.
func engineTopology(req api.Request, topoBytes []byte, rw *ipRewriter, hepRelocated bool) (string, error) {
	if !hepRelocated {
		return rw.rewriteText(string(topoBytes)), nil
	}
	out, err := yaml.Marshal(req)
	if err != nil {
		return "", err
	}
	return rw.rewriteText(string(out)), nil
}

// quarantineEntry is one flow that cannot be faithfully validated on the cluster.
type quarantineEntry struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

// loadQuarantine reads an optional quarantine.yaml from the case dir: flows that
// the engine and cluster legitimately can't be compared on (environment limits,
// not engine bugs). Returns a map keyed "from->to" to the reason. Absent file =
// no quarantine.
func loadQuarantine(t *testing.T, dir string) map[string]string {
	data, err := os.ReadFile(filepath.Join(dir, "quarantine.yaml"))
	if err != nil {
		return nil
	}
	var entries []quarantineEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		t.Fatalf("parse quarantine.yaml: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		out[e.From+"->"+e.To] = e.Reason
	}
	return out
}
