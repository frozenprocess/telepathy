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
const minimalFailsafes = `{"spec":{` +
	`"failsafeInboundHostPorts":[` +
	`{"protocol":"TCP","port":22},` + // ssh
	`{"protocol":"TCP","port":6443},` + // kube-apiserver (kind control-plane)
	`{"protocol":"TCP","port":2379},{"protocol":"TCP","port":2380},` + // etcd
	`{"protocol":"TCP","port":10250},` + // kubelet
	`{"protocol":"TCP","port":5473},` + // calico-typha
	`{"protocol":"TCP","port":179}` + // BGP
	`],` +
	`"failsafeOutboundHostPorts":[` +
	`{"protocol":"TCP","port":6443},` + // kubelet -> apiserver
	`{"protocol":"TCP","port":2379},{"protocol":"TCP","port":2380},` + // etcd
	`{"protocol":"UDP","port":53},{"protocol":"TCP","port":53},` + // DNS
	`{"protocol":"TCP","port":5473},` + // calico-node -> calico-typha
	`{"protocol":"TCP","port":179}` + // BGP
	`]}}`

// setFailsafes narrows Calico's failsafe host ports to minimalFailsafes while a
// HostEndpoint case runs (constrain=true), then restores them (constrain=false).
// Restoring is a merge patch with null, which drops the field so Felix falls
// back to its built-in defaults rather than to whatever was there before.
func setFailsafes(ctx context.Context, c *cluster, constrain bool) error {
	patch := `{"spec":{"failsafeInboundHostPorts":null,"failsafeOutboundHostPorts":null}}`
	if constrain {
		patch = minimalFailsafes
	}
	out, err := c.kubectl(ctx, nil, "patch", "felixconfiguration", "default",
		"--type", "merge", "-p", patch)
	if err != nil {
		return cmdErr(fmt.Sprintf("patch felixconfiguration failsafes (constrain=%v)", constrain), out, err)
	}
	return nil
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
// torn down afterwards, mirroring setFailsafes.
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
