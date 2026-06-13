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

package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"

	"antrea.io/antrea/pkg/controller/grouping"
	grouptypes "antrea.io/antrea/pkg/controller/types"

	"github.com/frozenprocess/telepathy/api"
)

// groupType is an arbitrary tag for the groups we register in the index; Antrea
// keys groups by (type, name) and any string works for resolution.
const groupType grouping.GroupType = "telepathy"

// model is the resolved policy set the evaluator works against. Selector
// resolution — which pods a podSelector/namespaceSelector matches — is done by
// Antrea's real grouping.GroupEntityIndex (the same engine its controller
// uses); the standardized Kubernetes NetworkPolicy verdict is computed over the
// resolved members in eval.go.
type model struct {
	policies []resolvedPolicy
	warnings []string
	errors   []string
}

// resolvedPolicy is one Kubernetes NetworkPolicy with its selectors already
// resolved to concrete pod identities ("namespace/name").
type resolvedPolicy struct {
	name           string
	ingressIsolate bool // pod selected by this policy is ingress-isolated
	egressIsolate  bool
	appliedTo      map[string]bool
	ingress        []resolvedRule
	egress         []resolvedRule
}

// resolvedRule is one ingress/egress rule: its peers resolved to pods + IP
// blocks, and its port matchers. matchAllPeers is the K8s "from/to: []" (or
// absent) allow-all form; empty ports means all ports.
type resolvedRule struct {
	matchAllPeers bool
	peerPods      map[string]bool
	ipBlocks      []resolvedIPBlock
	ports         []portSpec
}

type resolvedIPBlock struct {
	cidr   *net.IPNet
	except []*net.IPNet
}

// portSpec matches one (protocol, port[-endPort]) or a named port. port == -1
// with an empty name means "all ports of this protocol".
type portSpec struct {
	proto   string
	port    int
	endPort int
	named   string
}

// build constructs the GroupEntityIndex from req's topology and resolves every
// parsed Kubernetes NetworkPolicy against it.
func build(req api.Request) model {
	var m model
	b := &builder{idx: grouping.NewGroupEntityIndex()}

	for _, ns := range namespaceObjects(req) {
		b.idx.AddNamespace(ns)
	}
	for _, pod := range podObjects(req) {
		b.idx.AddPod(pod)
	}

	for _, p := range req.Policies {
		np, kind, err := parseK8sNetworkPolicy(p)
		switch {
		case err != nil:
			m.errors = append(m.errors, err.Error())
		case np != nil:
			m.policies = append(m.policies, b.resolvePolicy(np))
		default:
			m.warnings = append(m.warnings,
				fmt.Sprintf("antrea provider: skipping unsupported manifest kind %q "+
					"(only Kubernetes NetworkPolicy is evaluated)", kind))
		}
	}
	return m
}

// builder resolves selectors via the index, assigning each a unique group name.
type builder struct {
	idx *grouping.GroupEntityIndex
	n   int
}

// resolve registers a selector as a group and returns the matching pods as a
// set of "namespace/name". A nil nsSelector scopes to namespace; a non-nil one
// spans namespaces (namespace must be "") filtered by the selector.
func (b *builder) resolve(namespace string, podSel, nsSel *metav1.LabelSelector) map[string]bool {
	name := "g" + strconv.Itoa(b.n)
	b.n++
	b.idx.AddGroup(groupType, name, grouptypes.NewGroupSelector(namespace, podSel, nsSel, nil, nil))
	pods, _ := b.idx.GetEntities(groupType, name)
	out := make(map[string]bool, len(pods))
	for _, p := range pods {
		out[p.Namespace+"/"+p.Name] = true
	}
	return out
}

func (b *builder) resolvePolicy(np *networkingv1.NetworkPolicy) resolvedPolicy {
	rp := resolvedPolicy{
		name:           np.Namespace + "/" + np.Name,
		ingressIsolate: policyTypeHas(np, networkingv1.PolicyTypeIngress),
		egressIsolate:  policyTypeHas(np, networkingv1.PolicyTypeEgress),
		appliedTo:      b.resolve(np.Namespace, &np.Spec.PodSelector, nil),
	}
	for _, r := range np.Spec.Ingress {
		rp.ingress = append(rp.ingress, b.resolveRule(np.Namespace, r.From, r.Ports))
	}
	for _, r := range np.Spec.Egress {
		rp.egress = append(rp.egress, b.resolveRule(np.Namespace, r.To, r.Ports))
	}
	return rp
}

// resolveRule turns a rule's peers (From for ingress, To for egress) and ports
// into a resolvedRule. An empty peer list is allow-all.
func (b *builder) resolveRule(ns string, peers []networkingv1.NetworkPolicyPeer, ports []networkingv1.NetworkPolicyPort) resolvedRule {
	r := resolvedRule{peerPods: map[string]bool{}}
	if len(peers) == 0 {
		r.matchAllPeers = true
	}
	for _, peer := range peers {
		if peer.IPBlock != nil {
			if blk := parseIPBlock(peer.IPBlock); blk != nil {
				r.ipBlocks = append(r.ipBlocks, *blk)
			}
			continue
		}
		// Selector peer. With a namespaceSelector the match spans namespaces
		// (scope ""), filtered by it; without one it is the policy's namespace.
		scope := ns
		if peer.NamespaceSelector != nil {
			scope = ""
		}
		for k := range b.resolve(scope, peer.PodSelector, peer.NamespaceSelector) {
			r.peerPods[k] = true
		}
	}
	r.ports = parsePorts(ports)
	return r
}

// --- parsing helpers -------------------------------------------------------

func parsePorts(ports []networkingv1.NetworkPolicyPort) []portSpec {
	var out []portSpec
	for _, p := range ports {
		ps := portSpec{proto: "tcp", port: -1}
		if p.Protocol != nil {
			ps.proto = strings.ToLower(string(*p.Protocol))
		}
		if p.Port != nil {
			if p.Port.Type == intstr.Int {
				ps.port = p.Port.IntValue()
				ps.endPort = ps.port
				if p.EndPort != nil {
					ps.endPort = int(*p.EndPort)
				}
			} else {
				ps.named = p.Port.StrVal
			}
		}
		out = append(out, ps)
	}
	return out
}

func parseIPBlock(b *networkingv1.IPBlock) *resolvedIPBlock {
	_, cidr, err := net.ParseCIDR(b.CIDR)
	if err != nil {
		return nil
	}
	blk := &resolvedIPBlock{cidr: cidr}
	for _, ex := range b.Except {
		if _, exNet, err := net.ParseCIDR(ex); err == nil {
			blk.except = append(blk.except, exNet)
		}
	}
	return blk
}

// policyTypeHas reports whether a NetworkPolicy governs the given direction,
// applying the Kubernetes default: an unset policyTypes implies Ingress, and
// also Egress when the spec carries egress rules.
func policyTypeHas(np *networkingv1.NetworkPolicy, t networkingv1.PolicyType) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		switch t {
		case networkingv1.PolicyTypeIngress:
			return true
		case networkingv1.PolicyTypeEgress:
			return len(np.Spec.Egress) > 0
		}
	}
	for _, pt := range np.Spec.PolicyTypes {
		if pt == t {
			return true
		}
	}
	return false
}

// namespaceObjects builds a Namespace per declared namespace plus any namespace
// an endpoint references but that wasn't declared. The well-known
// kubernetes.io/metadata.name label (injected by the apiserver in a real
// cluster) is added so namespaceSelector rules that key off it resolve.
func namespaceObjects(req api.Request) []*corev1.Namespace {
	seen := map[string]map[string]string{}
	for _, ns := range req.Namespaces {
		labels := map[string]string{}
		for k, v := range ns.Labels {
			labels[k] = v
		}
		labels["kubernetes.io/metadata.name"] = ns.Name
		seen[ns.Name] = labels
	}
	for _, ep := range req.Endpoints {
		if ns := endpointNamespace(ep); ns != "" {
			if _, ok := seen[ns]; !ok {
				seen[ns] = map[string]string{"kubernetes.io/metadata.name": ns}
			}
		}
	}
	var out []*corev1.Namespace
	for name, labels := range seen {
		out = append(out, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}})
	}
	return out
}

// podObjects builds a Pod per workload endpoint (one with a namespace).
// Non-namespaced endpoints (external destinations / hosts) are not pods and are
// matched only by IP against rule IPBlocks at evaluation time.
func podObjects(req api.Request) []*corev1.Pod {
	var out []*corev1.Pod
	for _, ep := range req.Endpoints {
		ns := endpointNamespace(ep)
		if ns == "" {
			continue
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: endpointName(ep), Labels: ep.Labels},
			Spec:       corev1.PodSpec{NodeName: "telepathy-node"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		if ep.IP != "" {
			pod.Status.PodIP = ep.IP
			pod.Status.PodIPs = []corev1.PodIP{{IP: ep.IP}}
		}
		out = append(out, pod)
	}
	return out
}

// parseK8sNetworkPolicy decodes a manifest into a Kubernetes NetworkPolicy when
// it is one. It returns (nil, kind, nil) for any other kind so the caller can
// surface a skip warning, and (nil, kind, err) only on malformed input.
func parseK8sNetworkPolicy(p api.PolicyInput) (*networkingv1.NetworkPolicy, string, error) {
	var head struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	if err := yaml.Unmarshal([]byte(p.YAML), &head); err != nil {
		return nil, "", fmt.Errorf("antrea provider: cannot parse manifest: %v", err)
	}
	isK8sNP := head.Kind == "NetworkPolicy" &&
		(p.Flavor == "k8s" || strings.HasPrefix(head.APIVersion, "networking.k8s.io/"))
	if !isK8sNP {
		return nil, head.Kind, nil
	}
	var np networkingv1.NetworkPolicy
	if err := yaml.Unmarshal([]byte(p.YAML), &np); err != nil {
		return nil, head.Kind, fmt.Errorf("antrea provider: cannot decode NetworkPolicy: %v", err)
	}
	if np.Namespace == "" {
		np.Namespace = "default"
	}
	return &np, head.Kind, nil
}
