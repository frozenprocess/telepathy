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
	"fmt"
	"strconv"
	"strings"

	"github.com/frozenprocess/telepathy/api"
)

// --- yamlNode: a tiny indentation-aware YAML emitter --------------------------
//
// The harness renders the objects it applies as YAML text rather than marshalling
// typed structs, so it can keep full control over the few places Kubernetes YAML
// is finicky (notably Service targetPort's int-or-string rule). yamlNode replaces
// the per-manifest fmt.Fprintf blocks that used to be copied across realize.go and
// hep.go: every renderer now shares the same apiVersion/kind/metadata/labels
// scaffolding and the same value-quoting rules.
//
// A node is a cursor at a fixed indent into a shared buffer; child()/block()/item()
// descend a level. Keys/values written via scalar() and the label map are
// Go-quoted, which is valid YAML/JSON and safely carries the dots and slashes in
// labels like kubernetes.io/metadata.name; raw() emits a value verbatim for
// numbers and bare enum tokens.
type yamlNode struct {
	b   *strings.Builder
	ind string
}

// doc starts a new top-level document with apiVersion/kind already written.
func doc(apiVersion, kind string) *yamlNode {
	n := &yamlNode{b: &strings.Builder{}, ind: ""}
	n.raw("apiVersion", apiVersion)
	n.raw("kind", kind)
	return n
}

// line writes one indented, newline-terminated line.
func (n *yamlNode) line(format string, args ...any) *yamlNode {
	n.b.WriteString(n.ind)
	fmt.Fprintf(n.b, format, args...)
	n.b.WriteByte('\n')
	return n
}

// scalar writes `key: "value"` (value Go-quoted).
func (n *yamlNode) scalar(key, value string) *yamlNode { return n.line("%s: %q", key, value) }

// scalarIf writes scalar only when value is non-empty.
func (n *yamlNode) scalarIf(key, value string) *yamlNode {
	if value != "" {
		n.scalar(key, value)
	}
	return n
}

// raw writes `key: value` with the value unquoted (numbers, bare enums).
func (n *yamlNode) raw(key, value string) *yamlNode { return n.line("%s: %s", key, value) }

// rawIf writes raw only when value is non-empty.
func (n *yamlNode) rawIf(key, value string) *yamlNode {
	if value != "" {
		n.raw(key, value)
	}
	return n
}

// child returns a cursor one indent level deeper, sharing the same buffer.
func (n *yamlNode) child() *yamlNode { return &yamlNode{b: n.b, ind: n.ind + "  "} }

// block writes `key:` then renders fn against a deeper cursor.
func (n *yamlNode) block(key string, fn func(*yamlNode)) *yamlNode {
	n.line("%s:", key)
	fn(n.child())
	return n
}

// labels writes `key:` followed by the map as sorted, Go-quoted key/value pairs,
// in deterministic order. The whole block is omitted when the map is empty (which
// the API server treats identically to an empty labels map).
func (n *yamlNode) labels(key string, m map[string]string) *yamlNode {
	if len(m) == 0 {
		return n
	}
	return n.block(key, func(c *yamlNode) {
		for _, k := range sortedMapKeys(m) {
			c.line("%q: %q", k, m[k])
		}
	})
}

// item appends a `- ` sequence element whose body fn renders; the first body line
// carries the dash and continuation lines align under it.
func (n *yamlNode) item(fn func(*yamlNode)) *yamlNode {
	var sub strings.Builder
	fn(&yamlNode{b: &sub, ind: n.ind + "  "})
	body := strings.TrimPrefix(sub.String(), n.ind+"  ")
	n.b.WriteString(n.ind + "- " + body)
	return n
}

// scalarSeq writes `key:` then each value as a `- "value"` element at the same
// indent as the key (valid YAML, and the form the Calico nets/expectedIPs lists
// have always used). The key is written even for an empty slice.
func (n *yamlNode) scalarSeq(key string, values []string) *yamlNode {
	n.line("%s:", key)
	for _, v := range values {
		n.line("- %q", v)
	}
	return n
}

// String returns the rendered document.
func (n *yamlNode) String() string { return n.b.String() }

// --- container fragments shared by pod manifests ------------------------------

// netexecProcs returns the netexec invocations that together serve every port in
// plan. netexec binds one TCP (--http-port), one UDP (--udp-port) and optionally
// one SCTP (--sctp-port) port per process, so the first process carries tcp[0]/
// udp[0]/sctp[0] and every additional port of any protocol gets its own process.
// netexec always binds a UDP port, so a process added for an extra TCP port reuses
// that TCP port number for --udp-port (a TCP and a UDP bind on the same number
// don't conflict, and the TCP ports are distinct across processes).
func netexecProcs(plan serverPlan) [][]string {
	proc := func(args ...string) []string {
		return append([]string{"/agnhost", "netexec"}, args...)
	}
	first := []string{
		fmt.Sprintf("--http-port=%d", plan.tcp[0]),
		fmt.Sprintf("--udp-port=%d", plan.udp[0]),
	}
	if len(plan.sctp) > 0 {
		first = append(first, fmt.Sprintf("--sctp-port=%d", plan.sctp[0]))
	}
	procs := [][]string{proc(first...)}
	for _, p := range plan.tcp[1:] {
		procs = append(procs, proc(fmt.Sprintf("--http-port=%d", p), fmt.Sprintf("--udp-port=%d", p)))
	}
	for _, p := range plan.udp[1:] {
		procs = append(procs, proc(fmt.Sprintf("--http-port=%d", p), fmt.Sprintf("--udp-port=%d", p)))
	}
	if len(plan.sctp) > 1 {
		for _, p := range plan.sctp[1:] {
			procs = append(procs, proc(
				fmt.Sprintf("--http-port=%d", p),
				fmt.Sprintf("--udp-port=%d", p),
				fmt.Sprintf("--sctp-port=%d", p)))
		}
	}
	return procs
}

// agnhostCommand is the agnhost container entrypoint serving the case's probed
// ports. A single listener execs netexec directly; multiple listeners (a case
// probing one protocol on several ports) are launched in the background under a
// shell so one container serves them all.
func agnhostCommand(plan serverPlan) string {
	procs := netexecProcs(plan)
	if len(procs) == 1 {
		return jsonStrArray(procs[0])
	}
	parts := make([]string, len(procs))
	for i, p := range procs {
		parts[i] = strings.Join(p, " ") + " &"
	}
	return jsonStrArray([]string{"sh", "-c", strings.Join(parts, " ") + " wait"})
}

// jsonStrArray renders items as a JSON string array (a Pod command:). The strings
// are simple ASCII flags, so Go-quoting matches JSON quoting.
func jsonStrArray(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = strconv.Quote(s)
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

// appendAgnhostContainer adds the agnhost L4 server container to a `containers:`
// sequence. appendToolsContainer adds the netshoot sidecar (sleep infinity), the
// exec target for ICMP probes agnhost connect can't do. Both pod kinds (workload
// and host) share this pair, so it lives here once.
func appendAgnhostContainer(containers *yamlNode, image string, plan serverPlan) {
	containers.item(func(c *yamlNode) {
		c.raw("name", "agnhost")
		c.scalar("image", image)
		c.raw("command", agnhostCommand(plan))
	})
}

func appendToolsContainer(containers *yamlNode, image string) {
	containers.item(func(c *yamlNode) {
		c.raw("name", "tools")
		c.scalar("image", image)
		c.raw("command", `["sleep","infinity"]`)
	})
}

// --- object renderers ---------------------------------------------------------

// podManifest renders one endpoint as a Pod. The agnhost container serves the
// case's probed L4 ports; the netshoot sidecar is the exec target for ICMP.
// nodeName is set only when the topology pins a node that actually exists, so a
// stale `node:` value doesn't strand the pod in Pending.
func podManifest(e api.Endpoint, plan serverPlan, nodeExists map[string]bool, agnhost, netshoot string) string {
	d := doc("v1", "Pod")
	d.block("metadata", func(m *yamlNode) {
		m.scalar("name", e.Name)
		m.scalar("namespace", e.Namespace)
		m.labels("labels", e.Labels)
	})
	d.block("spec", func(s *yamlNode) {
		s.raw("terminationGracePeriodSeconds", "1")
		s.scalarIf("serviceAccountName", e.ServiceAccountName)
		if e.Node != "" && nodeExists[e.Node] {
			s.scalar("nodeName", e.Node)
		}
		s.block("containers", func(cs *yamlNode) {
			appendAgnhostContainer(cs, agnhost, plan)
			appendToolsContainer(cs, netshoot)
		})
	})
	return d.String()
}

// hostPodManifest renders a hostNetwork agnhost+netshoot pod pinned to a node. It
// is the dataplane realization of a HostEndpoint row/col: its pod IP equals the
// node InternalIP, and traffic to/from it is host traffic.
func hostPodManifest(name, node string, plan serverPlan, agnhost, netshoot string) string {
	d := doc("v1", "Pod")
	d.block("metadata", func(m *yamlNode) {
		m.scalar("name", name)
		m.scalar("namespace", hostNS)
		m.block("labels", func(l *yamlNode) { l.scalar("telepathy.host", "true") })
	})
	d.block("spec", func(s *yamlNode) {
		s.raw("hostNetwork", "true")
		s.raw("terminationGracePeriodSeconds", "1")
		s.scalar("nodeName", node)
		s.block("containers", func(cs *yamlNode) {
			appendAgnhostContainer(cs, agnhost, plan)
			appendToolsContainer(cs, netshoot)
		})
	})
	return d.String()
}

// serviceAccountManifest renders a ServiceAccount with labels. Calico projects
// these labels onto the pods that reference the SA (as pcsa.<k>=<v>), which is how
// `serviceAccounts.selector` rules resolve on the real cluster.
func serviceAccountManifest(sa api.ServiceAccountInput) string {
	d := doc("v1", "ServiceAccount")
	d.block("metadata", func(m *yamlNode) {
		m.scalar("name", sa.Name)
		m.scalar("namespace", sa.Namespace)
		m.labels("labels", sa.Labels)
	})
	return d.String()
}

// serviceManifest renders a Service. By default it's ClusterIP (the engine
// surfaces it as a `svc/<ns>/<name>` matrix column; on the cluster we probe its
// ClusterIP). When s.Type is NodePort the Service also exposes a per-node port, so
// an off-cluster observer can reach a backend via node-IP:nodePort — the
// externally routable path a preDNAT/NodePort case needs.
func serviceManifest(s api.ServiceInput) string {
	d := doc("v1", "Service")
	d.block("metadata", func(m *yamlNode) {
		m.scalar("name", s.Name)
		m.scalar("namespace", s.Namespace)
	})
	d.block("spec", func(sp *yamlNode) {
		sp.rawIf("type", s.Type)
		sp.labels("selector", s.Selector)
		if len(s.Ports) == 0 {
			return
		}
		sp.block("ports", func(ps *yamlNode) {
			for _, p := range s.Ports {
				proto := p.Protocol
				if proto == "" {
					proto = "TCP"
				}
				ps.item(func(pi *yamlNode) {
					pi.raw("port", strconv.Itoa(p.Port))
					pi.raw("protocol", strings.ToUpper(proto))
					if p.NodePort != 0 {
						pi.raw("nodePort", strconv.Itoa(p.NodePort))
					}
					tp := p.TargetPort
					if tp == "" {
						tp = strconv.Itoa(p.Port)
					}
					// Kubernetes targetPort is an int-or-string: a numeric value must
					// be emitted unquoted (an integer), while a named port (containing
					// a letter) must be a quoted string. Quoting a numeric value makes
					// the API server treat it as a named port and reject it.
					if _, err := strconv.Atoi(tp); err == nil {
						pi.raw("targetPort", tp)
					} else {
						pi.scalar("targetPort", tp)
					}
				})
			}
		})
	})
	return d.String()
}

// networkSetManifest / globalNetworkSetManifest render Calico (Global)NetworkSets.
// Nets are expected to be already IP-remapped by the caller (see ipmap.go) so the
// set contains the real pod IPs the policy is meant to match.
func networkSetManifest(n api.NetworkSetInput) string {
	d := doc("projectcalico.org/v3", "NetworkSet")
	d.block("metadata", func(m *yamlNode) {
		m.scalar("name", n.Name)
		m.scalar("namespace", n.Namespace)
		m.labels("labels", n.Labels)
	})
	d.block("spec", func(s *yamlNode) { s.scalarSeq("nets", n.Nets) })
	return d.String()
}

func globalNetworkSetManifest(n api.GlobalNetworkSetInput) string {
	d := doc("projectcalico.org/v3", "GlobalNetworkSet")
	d.block("metadata", func(m *yamlNode) {
		m.scalar("name", n.Name)
		m.labels("labels", n.Labels)
	})
	d.block("spec", func(s *yamlNode) { s.scalarSeq("nets", n.Nets) })
	return d.String()
}

// hostEndpointManifest renders a Calico HostEndpoint. expectedIPs is expected to
// already hold the real node InternalIP (remapped from the topology's fictional
// value). interfaceName defaults to "*" (all interfaces) when unset.
func hostEndpointManifest(h api.HostEndpointInput) string {
	d := doc("projectcalico.org/v3", "HostEndpoint")
	d.block("metadata", func(m *yamlNode) {
		m.scalar("name", h.Name)
		m.labels("labels", h.Labels)
	})
	d.block("spec", func(s *yamlNode) {
		s.scalarIf("node", h.Node)
		iface := h.InterfaceName
		if iface == "" {
			iface = "*"
		}
		s.scalar("interfaceName", iface)
		if len(h.ExpectedIPs) > 0 {
			s.scalarSeq("expectedIPs", h.ExpectedIPs)
		}
	})
	return d.String()
}
