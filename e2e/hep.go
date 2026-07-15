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
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// hostNS is the namespace that holds the hostNetwork pods standing in for Calico
// HostEndpoints. A hostNetwork pod shares its node's network namespace, so a
// flow exec'd from it originates from the node IP and is policed by the node's
// HostEndpoint — exactly the "host/<name>" actor the engine models.
const hostNS = "telepathy-host"

// minimalFailsafes is the control-plane-only failsafe set used while a HEP case
// runs. Calico's failsafe rules unconditionally ALLOW their listed ports, which
// would mask the policy under test if the probe targeted one of them — so we
// strip the failsafe list down to just the ports the node genuinely needs to
// stay reachable (kube-apiserver, etcd, kubelet, ssh, BGP, DNS). The probe
// ports (8080/8081/9000) are deliberately absent, so the HostEndpoint policy,
// not a failsafe, decides those flows. This is the targeted alternative to
// blanking the list entirely, which would also drop apiserver/etcd and risk
// wedging the node.
// Note 5473 (Typha): a *-interface HEP subjects the node's own host traffic to
// policy, and Calico's calico-node↔calico-typha control connection rides 5473.
// If it's not a failsafe, narrowing the list severs Typha discovery and
// calico-node crash-loops cluster-wide ("Typha discovery failed"), which
// degrades the dataplane for the whole run — so it MUST stay open in both
// directions even while we narrow everything else.
// Note 4789 (VXLAN): same reasoning. Cross-node POD traffic on a VXLAN cluster
// is UDP/4789 encapped between node IPs; a *-interface HEP polices that host
// traffic too, so if 4789 isn't a failsafe every cross-node pod flow is dropped
// while the HEP case runs — and the dropped flows leave INVALID conntrack that
// keeps being dropped after teardown, poisoning later cases with control-plane
// pods (a false-deny "no route to host"/timeout unrelated to the policy). Must
// stay open both directions, like BGP/Typha.
const minimalFailsafes = `{"spec":{` +
	`"failsafeInboundHostPorts":[` +
	`{"protocol":"TCP","port":22},` + // ssh
	`{"protocol":"TCP","port":6443},` + // kube-apiserver (kind control-plane)
	`{"protocol":"TCP","port":2379},{"protocol":"TCP","port":2380},` + // etcd
	`{"protocol":"TCP","port":10250},` + // kubelet
	`{"protocol":"TCP","port":5473},` + // calico-typha
	`{"protocol":"UDP","port":4789},` + // VXLAN (cross-node pod overlay)
	`{"protocol":"TCP","port":179}` + // BGP
	`],` +
	`"failsafeOutboundHostPorts":[` +
	`{"protocol":"TCP","port":6443},` + // kubelet -> apiserver
	`{"protocol":"TCP","port":2379},{"protocol":"TCP","port":2380},` + // etcd
	`{"protocol":"UDP","port":53},{"protocol":"TCP","port":53},` + // DNS
	`{"protocol":"TCP","port":5473},` + // calico-node -> calico-typha
	`{"protocol":"UDP","port":4789},` + // VXLAN (cross-node pod overlay)
	`{"protocol":"TCP","port":179}` + // BGP
	`]}}`

// narrowFailsafes narrows Calico's failsafe host ports to minimalFailsafes so a
// HostEndpoint case's policy (not a failsafe) decides the probe ports. It is
// NEVER restored per-case, on purpose: changing FailsafeInbound/OutboundHostPorts
// forces a full Felix restart on every node (Calico requires it), and that
// restart briefly severs calico-node↔apiserver — stranding any pod scheduled
// meanwhile in ContainerCreating and poisoning the next case. So narrow once and
// leave it: the patch is idempotent (re-patching identical values is a no-op, no
// restart), and narrowed failsafes are inert on nodes with no HostEndpoint, so
// non-HEP cases are unaffected. The single restart happens on the first HEP
// case's narrow, after its pods already exist, and its settle absorbs it.
func narrowFailsafes(ctx context.Context, c *cluster) error {
	out, err := c.kubectl(ctx, nil, "patch", "felixconfiguration", "default",
		"--type", "merge", "-p", minimalFailsafes)
	if err != nil {
		return cmdErr("patch felixconfiguration failsafes (narrow)", out, err)
	}
	return nil
}

// repairLeakedHEPState undoes a HostEndpoint a prior case leaked by NOT running
// its teardown: a timed-out (`go test -timeout`) or killed run never runs
// t.Cleanup, so its HostEndpoints persist. A leaked HostEndpoint on the
// control-plane node default-drops FORWARDED (cross-node) pod traffic — silently
// poisoning every later case — and tigerastatus stays Available throughout, so
// ensureClusterHealthy can't see it. The per-case deleteOrphanClusterPolicies
// reaps the object but --wait=false, so the dataplane drop chains can outlive
// it. This does the synchronous repair, but ONLY when a leak is detected — a
// clean run pays one get. Calico only.
//
// Narrowed failsafes are NOT treated as a leak: narrowing is idempotent and
// inert without a HostEndpoint, and is deliberately left in place across cases
// (toggling FailsafeHostPorts forces a Felix restart — see narrowFailsafes), so a
// leaked narrow needs no repair; deleting the orphan HEP is enough.
func repairLeakedHEPState(ctx context.Context, t *testing.T, c *cluster) {
	if cfg.Provider != "calico" {
		return
	}
	heps, err := c.kubectl(ctx, nil, "get", "hostendpoints.projectcalico.org",
		"-l", "app.kubernetes.io/managed-by!=tigera-operator",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		t.Logf("repair HEP state: list hostendpoints: %v\n%s", err, heps)
		return
	}
	if strings.TrimSpace(heps) == "" {
		return // clean baseline — the common path
	}
	t.Logf("repairing leaked HostEndpoints from an interrupted prior run: %q", strings.TrimSpace(heps))

	// Delete the orphan HostEndpoints and WAIT — removing them lifts the
	// applyOnForward drop that poisons cross-node traffic.
	if out, err := c.kubectl(ctx, nil, "delete", "hostendpoints.projectcalico.org",
		"-l", "app.kubernetes.io/managed-by!=tigera-operator",
		"--ignore-not-found", "--wait=true", "--timeout=60s"); err != nil {
		t.Logf("repair HEP state: delete hostendpoints: %v\n%s", err, out)
	}
	// The node-subnet IPPool is the other half of a HEP case's leaked state (its
	// teardown deletes it too); reap it so a leaked pool over the node subnet
	// can't linger. deleteOrphanClusterPolicies handles the GNP/GNS.
	if out, err := c.kubectl(ctx, nil, "delete", "ippool", nodeSubnetPool,
		"--ignore-not-found", "--wait=true", "--timeout=60s"); err != nil {
		t.Logf("repair HEP state: delete node-subnet IPPool: %v\n%s", err, out)
	}
	// Felix needs a moment to pull the forward chains once the HEP is gone; flush
	// conntrack so no established entry masks the change, then let it converge.
	if nodes, err := c.nodes(ctx); err == nil {
		names := make([]string, 0, len(nodes))
		for n := range nodes {
			names = append(names, n)
		}
		flushConntrack(ctx, c, names)
	}
	time.Sleep(cfg.HEPSettleDelay)
}

// nodeSubnetPool is the name of the temporary disabled IPPool the HEP harness
// creates to cover the kind node subnet (see nodeSubnetPoolManifest).
const nodeSubnetPool = "telepathy-node-subnet"

// nodeSubnetCIDR derives the /16 that covers a node InternalIP. kind places all
// its nodes on a single docker bridge (default 172.18.0.0/16); masking any node
// IP to /16 yields a CIDR that covers every node regardless of the exact bridge
// subnet docker happened to assign.
func nodeSubnetCIDR(nodeIP string) (string, error) {
	ip := net.ParseIP(nodeIP).To4()
	if ip == nil {
		return "", fmt.Errorf("node IP %q is not IPv4", nodeIP)
	}
	return fmt.Sprintf("%d.%d.0.0/16", ip[0], ip[1]), nil
}

// nodeSubnetPoolManifest renders a *disabled* Calico IPPool covering the kind
// node subnet. The pod pool has natOutgoing enabled, so Calico SNATs pod->node-IP
// traffic to the source node (the node IP sits outside every Calico pool) — which
// hides the source pod's labels from a HostEndpoint and makes the HEP's ingress
// policy unmatchable, so the dataplane allows a flow the policy means to deny.
// A disabled pool is never used for IPAM, but its CIDR still counts as "inside
// Calico" for the natOutgoing decision, so pod->node-IP keeps the real pod
// source IP and the HEP can resolve the pod's labels. Scoped to HEP cases and
// torn down afterwards.
func nodeSubnetPoolManifest(cidr string) string {
	return fmt.Sprintf("apiVersion: projectcalico.org/v3\nkind: IPPool\n"+
		"metadata:\n  name: %q\nspec:\n  cidr: %q\n  disabled: true\n  natOutgoing: false\n",
		nodeSubnetPool, cidr)
}

// flushConntrack clears connection tracking on each node so a freshly applied
// (or removed) doNotTrack policy isn't shadowed by a pre-existing established
// conntrack entry. Best-effort: the tool may be absent on a node, which is not
// fatal to the case.
func flushConntrack(ctx context.Context, c *cluster, nodes []string) {
	for _, n := range nodes {
		_, _ = c.dockerExec(ctx, n, "conntrack", "-F")
	}
}
