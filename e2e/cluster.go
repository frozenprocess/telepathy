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
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// cluster is a thin wrapper around the `kubectl` and `docker` CLIs bound to one
// kind cluster's context. The harness shells out rather than depending on
// client-go: the engine itself needs no Kubernetes client, and keeping that
// true means the e2e build tag adds no new module dependency.
type cluster struct {
	name string // kind cluster name, e.g. "telepathy-e2e"
	ctx  string // kubeconfig context, e.g. "kind-telepathy-e2e"
}

// newCluster resolves the kind cluster from cfg.ClusterName (CLUSTER_NAME, matching
// hacks/provision/calico-up.sh, whose --name flag overrides the name in
// calico-kind.yaml) and confirms the context is reachable. The default mirrors
// calico-up.sh's CLUSTER_NAME default.
func newCluster() (*cluster, error) {
	name := cfg.ClusterName
	c := &cluster{name: name, ctx: "kind-" + name}
	if out, err := c.kubectl(context.Background(), nil, "version", "-o", "json"); err != nil {
		return nil, cmdErr(fmt.Sprintf("cluster %q (context %s) not reachable", name, c.ctx), out, err)
	}
	return c, nil
}

// kubectl runs `kubectl --context <ctx> <args...>`, feeding stdin if non-nil,
// and returns combined output. The caller decides whether a non-zero exit is
// fatal (apply) or expected (a probe that should be denied).
func (c *cluster) kubectl(ctx context.Context, stdin []byte, args ...string) (string, error) {
	full := append([]string{"--context", c.ctx}, args...)
	cmd := exec.CommandContext(ctx, "kubectl", full...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// apply client-side applies a multi-document manifest from stdin. We avoid
// server-side apply on purpose: Calico's aggregated apiserver doesn't fully
// support SSA for projectcalico.org resources (the apply PATCH fails with a
// spurious NotFound rather than creating), and our manifests are small enough
// that the last-applied-annotation size limit is never a concern.
func (c *cluster) apply(ctx context.Context, manifest string) (string, error) {
	return c.kubectl(ctx, []byte(manifest), "apply", "-f", "-")
}

// deleteManifest best-effort removes everything in a manifest. Errors are
// returned but callers in teardown paths typically only log them — a partially
// applied case must still clean up what landed.
func (c *cluster) deleteManifest(ctx context.Context, manifest string) (string, error) {
	return c.kubectl(ctx, []byte(manifest), "delete", "--ignore-not-found", "--wait=false", "-f", "-")
}

// clusterScopedPolicyKinds lists the cluster-scoped policy CRDs each provider
// installs. Only these exist on that provider's cluster; asking kubectl to
// delete another provider's kinds fails with "the server doesn't have a
// resource type" (which --ignore-not-found does NOT suppress — that only covers
// missing instances of a known type). A provider absent from the map has no
// cluster-scoped policy CRDs to reap.
var clusterScopedPolicyKinds = map[string]string{
	"calico": "globalnetworkpolicies.projectcalico.org,globalnetworksets.projectcalico.org,hostendpoints.projectcalico.org",
	"cilium": "ciliumclusterwidenetworkpolicies.cilium.io",
}

// Remove all left-over's from an E2E run in the cluster.
func (c *cluster) deleteOrphanClusterPolicies(ctx context.Context) (string, error) {
	kinds := clusterScopedPolicyKinds[cfg.Provider]
	if kinds == "" {
		return "", nil
	}
	return c.kubectl(ctx, nil, "delete", kinds,
		"-l", "app.kubernetes.io/managed-by!=tigera-operator",
		"--ignore-not-found", "--wait=false")
}

// protectedNamespaces are cluster namespaces the harness must never delete: they
// belong to Kubernetes or the CNI install, not to any case. A case may name one
// (so its pods can route to a service that lives there, modelled via a stand-in),
// and ensureNamespace relabels it additively, but pre-clean and teardown skip it.
var protectedNamespaces = map[string]bool{
	"default":          true,
	"kube-system":      true,
	"kube-public":      true,
	"kube-node-lease":  true,
	"calico-system":    true,
	"calico-apiserver": true,
	"tigera-operator":  true,
}

// protectedNamespace reports whether ns is a system namespace the harness must
// not delete. See protectedNamespaces.
func protectedNamespace(ns string) bool {
	return protectedNamespaces[ns]
}

// ensureNamespace creates ns if absent and (re)applies its labels without taking
// apply-ownership of it. Using create+label rather than `apply -f` on a
// Namespace object means pre-existing system namespaces (kube-system, default)
// are relabeled additively instead of being adopted and torn down. Returns
// created=true only when this call created the namespace, so teardown deletes
// exactly the namespaces the harness owns.
func (c *cluster) ensureNamespace(ctx context.Context, ns string, labels map[string]string) (created bool, err error) {
	if _, err := c.kubectl(ctx, nil, "get", "ns", ns); err != nil {
		if out, cerr := c.kubectl(ctx, nil, "create", "ns", ns); cerr != nil {
			// A racing create (parallel-safe) is fine; anything else is fatal.
			if !strings.Contains(out, "AlreadyExists") {
				return false, cmdErr("create ns "+ns, out, cerr)
			}
		} else {
			created = true
		}
	}
	for k, v := range labels {
		if out, err := c.kubectl(ctx, nil, "label", "ns", ns, fmt.Sprintf("%s=%s", k, v), "--overwrite"); err != nil {
			return created, cmdErr(fmt.Sprintf("label ns %s %s=%s", ns, k, v), out, err)
		}
	}
	return created, nil
}

// deleteNamespace removes a namespace and waits for it to be gone, so the next
// case can recreate it with different labels without a conflict. Namespace
// deletion is the cascade that reaps the case's pods/SAs/services.
func (c *cluster) deleteNamespace(ctx context.Context, ns string) error {
	_, err := c.kubectl(ctx, nil, "delete", "ns", ns, "--ignore-not-found", "--wait=true", "--timeout=120s")
	return err
}

// waitPodsReady blocks until every pod in ns is Ready or the deadline passes.
func (c *cluster) waitPodsReady(ctx context.Context, ns string, timeout time.Duration) (string, error) {
	return c.kubectl(ctx, nil,
		"wait", "-n", ns, "--for=condition=Ready", "pod", "--all",
		fmt.Sprintf("--timeout=%ds", int(timeout.Seconds())))
}

// waitServerListening polls until agnhost inside the pod accepts a TCP
// connection on port, checked over LOOPBACK via `kubectl exec` — so it never
// depends on cross-node routing. Pod-Ready only means the container is Running
// (agnhost carries no readinessProbe: a kubelet TCP probe dials the pod IP, and
// the control-plane node's kubelet can't route to pod IPs in kind+Calico, so it
// hangs 0/1 there). Without this, a probe can race netexec's bind and an allow
// flow reads as a false deny. Returns nil once serving, or an error after ~15s.
func (c *cluster) waitServerListening(ctx context.Context, ns, pod string, port int) error {
	target := fmt.Sprintf("127.0.0.1:%d", port)
	var last string
	for i := 0; i < 30; i++ {
		out, err := c.exec(ctx, ns, pod, "agnhost", "/agnhost", "connect", target, "--timeout=1s")
		if err == nil {
			return nil
		}
		last = out
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("agnhost not serving on %s after 15s: %s", target, strings.TrimSpace(last))
}

// calicoSystemNS is the namespace the Tigera operator installs Calico into.
const calicoSystemNS = "calico-system"

// waitTigeraAvailable blocks until every Calico tigerastatus component reports
// condition Available=True (apiserver, calico, ippools, …). The Tigera operator
// installs the tigerastatus CRD, so this is Calico-specific — callers gate on
// the provider. A component that is Degraded keeps Available=False, so this
// returns an error (timeout) for a flapping cluster, which is the signal
// ensureClusterHealthy uses to decide a restart is needed.
func (c *cluster) waitTigeraAvailable(ctx context.Context, timeout time.Duration) (string, error) {
	return c.kubectl(ctx, nil,
		"wait", "--for=condition=Available", "tigerastatus", "--all",
		fmt.Sprintf("--timeout=%ds", int(timeout.Seconds())))
}

// restartCalicoNode rolls ONLY the calico-node DaemonSet — the per-node dataplane
// (Felix/BIRD) whose programmed state a HostEndpoint case perturbs via narrowed
// failsafes and flushed conntrack — and waits for the rollout to finish.
//
// Deliberately scoped to calico-node, and deliberately a `rollout restart` (which
// the DaemonSet rolls one node at a time, maxUnavailable=1) rather than a blunt
// delete-all: restarting calico-apiserver / calico-kube-controllers alongside it,
// or cycling every node at once, forces Typha into a full relist whose CPU spike
// trips Typha's own health probes under the pods' cgroup CPU limits — Typha gets
// killed, calico-node loses its only Typha endpoint, and the whole dataplane
// falls into a crash loop it can't climb out of. A one-node-at-a-time dataplane
// roll keeps Typha and the apiserver untouched, so recovery stays bounded.
func (c *cluster) restartCalicoNode(ctx context.Context, timeout time.Duration) (string, error) {
	if out, err := c.kubectl(ctx, nil, "-n", calicoSystemNS, "rollout", "restart", "daemonset/calico-node"); err != nil {
		return out, cmdErr("rollout restart daemonset/calico-node", out, err)
	}
	out, err := c.kubectl(ctx, nil, "-n", calicoSystemNS, "rollout", "status", "daemonset/calico-node",
		fmt.Sprintf("--timeout=%ds", int(timeout.Seconds())))
	if err != nil {
		return out, cmdErr("rollout status daemonset/calico-node", out, err)
	}
	return out, nil
}

// restartCalicoControlPlane rolls the Calico *control-plane* Deployments
// (calico-apiserver, calico-kube-controllers) and waits for each to finish. A
// HEP case can strand these pods on a worker node whose apiserver-ClusterIP path
// it disrupts; when both apiserver replicas land there, the Calico aggregated API
// (GlobalNetworkPolicy/HostEndpoint/IPPool) goes down — and once it's down,
// nothing can delete the leaked objects that keep it down (delete needs that
// API). Rolling reschedules them so the API answers again. Sequential, and only
// invoked from the unhealthy recovery path — NOT alongside a calico-node roll:
// these Deployments talk to the k8s apiserver, not Typha, so rolling them alone
// doesn't trigger the Typha relist storm restartCalicoNode guards against.
func (c *cluster) restartCalicoControlPlane(ctx context.Context, timeout time.Duration) (string, error) {
	for _, deploy := range []string{"deployment/calico-apiserver", "deployment/calico-kube-controllers"} {
		if out, err := c.kubectl(ctx, nil, "-n", calicoSystemNS, "rollout", "restart", deploy); err != nil {
			return out, cmdErr("rollout restart "+deploy, out, err)
		}
		if out, err := c.kubectl(ctx, nil, "-n", calicoSystemNS, "rollout", "status", deploy,
			fmt.Sprintf("--timeout=%ds", int(timeout.Seconds()))); err != nil {
			return out, cmdErr("rollout status "+deploy, out, err)
		}
	}
	return "", nil
}

// podIP returns a pod's primary IP (empty until it has one).
func (c *cluster) podIP(ctx context.Context, ns, name string) (string, error) {
	out, err := c.kubectl(ctx, nil, "get", "pod", "-n", ns, name, "-o", "jsonpath={.status.podIP}")
	return strings.TrimSpace(out), err
}

// serviceClusterIP returns a Service's ClusterIP.
func (c *cluster) serviceClusterIP(ctx context.Context, ns, name string) (string, error) {
	out, err := c.kubectl(ctx, nil, "get", "svc", "-n", ns, name, "-o", "jsonpath={.spec.clusterIP}")
	return strings.TrimSpace(out), err
}

// nodes returns the set of node names in the cluster, used to decide whether a
// topology's `node:` pin (e.g. telepathy-e2e-calico-worker) actually exists before we set
// it on a pod — an unknown node name would wedge the pod in Pending forever.
func (c *cluster) nodes(ctx context.Context) (map[string]bool, error) {
	out, err := c.kubectl(ctx, nil, "get", "nodes", "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return nil, cmdErr("list nodes", out, err)
	}
	set := map[string]bool{}
	for _, n := range strings.Fields(out) {
		set[n] = true
	}
	return set, nil
}

// workerNodes returns all non-control-plane nodes (sorted by kubectl's output
// order). HostEndpoint placement prefers these so an enforced host policy can't
// sever the API server / etcd on the control-plane.
func (c *cluster) workerNodes(ctx context.Context) ([]string, error) {
	out, err := c.kubectl(ctx, nil, "get", "nodes",
		"-l", "!node-role.kubernetes.io/control-plane",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return nil, cmdErr("list worker nodes", out, err)
	}
	return strings.Fields(out), nil
}

// controlPlaneNodes returns the set of control-plane node names.
func (c *cluster) controlPlaneNodes(ctx context.Context) (map[string]bool, error) {
	out, err := c.kubectl(ctx, nil, "get", "nodes",
		"-l", "node-role.kubernetes.io/control-plane",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return nil, cmdErr("list control-plane nodes", out, err)
	}
	set := map[string]bool{}
	for _, n := range strings.Fields(out) {
		set[n] = true
	}
	return set, nil
}

// windowsNodes returns the set of Windows node names (kubernetes.io/os=windows).
// Used by the diagnostics dump to pick the right calico-node DaemonSet and the
// HNS-vs-iptables dataplane reader per node.
func (c *cluster) windowsNodes(ctx context.Context) (map[string]bool, error) {
	out, err := c.kubectl(ctx, nil, "get", "nodes",
		"-l", "kubernetes.io/os=windows",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return nil, cmdErr("list windows nodes", out, err)
	}
	set := map[string]bool{}
	for _, n := range strings.Fields(out) {
		set[n] = true
	}
	return set, nil
}

// nodeInternalIP returns a node's InternalIP — the address a HostEndpoint
// "host/<name>" row/col is probed at.
func (c *cluster) nodeInternalIP(ctx context.Context, node string) (string, error) {
	out, err := c.kubectl(ctx, nil, "get", "node", node,
		"-o", "jsonpath={.status.addresses[?(@.type=='InternalIP')].address}")
	return strings.TrimSpace(out), err
}

// exec runs a command inside a pod container and returns combined output plus
// the error (nil exit => nil error). Used for connectivity probes, where a
// non-nil error means the connection was refused/dropped.
func (c *cluster) exec(ctx context.Context, ns, pod, container string, argv ...string) (string, error) {
	args := []string{"exec", "-n", ns, pod}
	if container != "" {
		args = append(args, "-c", container)
	}
	args = append(args, "--")
	args = append(args, argv...)
	return c.kubectl(ctx, nil, args...)
}

// dockerExec runs a command inside a Docker container (a kind node — named
// after the node — or an external observer container the harness launched).
// HostEndpoint probes use this to originate/terminate traffic on the node
// itself and to manage conntrack/failsafe state unreachable through kubectl;
// external-observer probes use it to originate off-cluster traffic.
func (c *cluster) dockerExec(ctx context.Context, container string, argv ...string) (string, error) {
	return c.docker(ctx, append([]string{"exec", container}, argv...)...)
}

// docker runs a `docker` CLI subcommand and returns combined output.
func (c *cluster) docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// nodeNetwork returns the name of the Docker network a kind node is attached to
// (the bridge an external observer must join to reach node IPs / NodePorts).
// kind's default is "kind"; we read it back rather than assume, so a
// non-default network name still works.
func (c *cluster) nodeNetwork(ctx context.Context, node string) (string, error) {
	out, err := c.docker(ctx, "inspect", "-f",
		"{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", node)
	if err != nil {
		return "", cmdErr(fmt.Sprintf("inspect node %s network", node), out, err)
	}
	if nets := strings.Fields(out); len(nets) > 0 {
		return nets[0], nil
	}
	return "", fmt.Errorf("node %s has no docker network", node)
}

// startObserver launches a detached agnhost container on the given network and
// returns its IP on that network. It runs netexec serving the case's ports (the
// same server the cluster pods run), so the container works both as an
// off-cluster probe *source* (`docker exec … /agnhost connect`) and as an
// off-cluster *destination* a cluster pod can reach — the deterministic,
// same-network stand-in for a real internet address (no ICMP-to-public-IP
// dependency). It then polls until netexec is accepting connections, so a probe
// never races the server's startup. A pre-existing container of the same name is
// removed first so a crashed prior run can't wedge the launch.
func (c *cluster) startObserver(ctx context.Context, name, network, image string, plan serverPlan) (string, error) {
	_, _ = c.docker(ctx, "rm", "-f", name)

	// Serve every port the pods serve. One netexec process per (tcp,udp[,sctp])
	// group (see netexecProcs); multiple procs are backgrounded under sh.
	procs := netexecProcs(plan)
	run := []string{"run", "-d", "--name", name, "--network", network}
	if len(procs) == 1 {
		run = append(run, "--entrypoint", procs[0][0], image)
		run = append(run, procs[0][1:]...)
	} else {
		parts := make([]string, len(procs))
		for i, p := range procs {
			parts[i] = strings.Join(p, " ") + " &"
		}
		run = append(run, "--entrypoint", "sh", image, "-c", strings.Join(parts, " ")+" wait")
	}
	if out, err := c.docker(ctx, run...); err != nil {
		return "", cmdErr(fmt.Sprintf("run observer %s", name), out, err)
	}

	ip, err := c.docker(ctx, "inspect", "-f",
		fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}", network), name)
	if err != nil {
		return "", cmdErr(fmt.Sprintf("inspect observer %s ip", name), ip, err)
	}
	if ip = strings.TrimSpace(ip); ip == "" {
		return "", fmt.Errorf("observer %s has no IP on network %s", name, network)
	}

	// Wait for netexec to bind, mirroring the pods' readinessProbe. Probe the
	// primary TCP port from inside the container (loopback), so this checks the
	// server is up without depending on cross-network routing.
	target := fmt.Sprintf("127.0.0.1:%d", plan.tcp[0])
	var lastOut string
	for i := 0; i < 30; i++ {
		out, execErr := c.docker(ctx, "exec", name, "/agnhost", "connect", target, "--timeout=1s")
		if execErr == nil {
			return ip, nil
		}
		lastOut = out
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("observer %s netexec not serving on %s after 15s: %s", name, target, strings.TrimSpace(lastOut))
}

// removeObserver force-removes an observer container (best effort).
func (c *cluster) removeObserver(ctx context.Context, name string) {
	_, _ = c.docker(ctx, "rm", "-f", name)
}

// serviceNodePort returns the allocated nodePort of a Service's first port.
func (c *cluster) serviceNodePort(ctx context.Context, ns, name string) (int, error) {
	out, err := c.kubectl(ctx, nil, "get", "svc", "-n", ns, name,
		"-o", "jsonpath={.spec.ports[0].nodePort}")
	if err != nil {
		return 0, cmdErr(fmt.Sprintf("get nodePort for %s/%s", ns, name), out, err)
	}
	return strconv.Atoi(strings.TrimSpace(out))
}
