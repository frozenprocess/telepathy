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
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/u8proto"
	policyv1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	"sigs.k8s.io/yaml"

	"github.com/frozenprocess/telepathy/api"
)

// firstUserIdentity is where we start numbering fabricated pod identities.
// Below identity.MinimalNumericIdentity (256) is the reserved range (world,
// host, remote-node, …); user identities live at/above it.
const firstUserIdentity = 256

// evaluate computes the pod-to-pod connectivity matrix for req by driving
// Cilium's own policy engine offline: one fabricated identity per endpoint
// (labels + namespace), rules loaded via CiliumNetworkPolicy.Parse ->
// Repository.MustAddList, then policy.LookupFlow per src->dst pair. A flow is
// "allow" iff LookupFlow reports neither src-egress nor dst-ingress denied —
// Cilium's two-sided enforcement, matching the Calico/Antrea providers.
//
// ponytail: O(n^2) LookupFlow calls (one full policy resolution per ordered
// endpoint pair). Fine for topology-sized inputs; cache per-source
// SelectorPolicy if a large matrix ever gets slow.
func evaluate(req api.Request) api.Response {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Process-wide default: enforce policy only for endpoints a policy selects
	// (Cilium's normal mode). ponytail: package global, so one enforcement mode
	// per process — irrelevant for a single-shot CLI.
	policy.SetPolicyEnabled(option.DefaultEnforcement)

	resp := api.Response{Matrix: map[string]string{}}

	// Namespace name -> its labels, so we can project them onto pod identities
	// (Cilium exposes a namespace's labels on every pod in it — see endpointLabels).
	nsLabels := make(map[string]map[string]string, len(req.Namespaces))
	for _, ns := range req.Namespaces {
		nsLabels[ns.Name] = ns.Labels
	}

	// 1. Fabricate an identity per endpoint. Distinct numeric IDs even when
	// labels collide — selectors match on labels, so identical-label endpoints
	// get identical verdicts anyway.
	idents := make([]*identity.Identity, len(req.Endpoints))
	idMap := identity.IdentityMap{}
	namedTCP := make([]map[string]uint16, len(req.Endpoints))
	namedUDP := make([]map[string]uint16, len(req.Endpoints))
	for i, ep := range req.Endpoints {
		id := identity.NewIdentity(identity.NumericIdentity(firstUserIdentity+i), endpointLabels(ep, nsLabels))
		idents[i] = id
		idMap[id.ID] = id.LabelArray
		namedTCP[i], namedUDP[i] = namedPorts(ep, "tcp"), namedPorts(ep, "udp")
	}

	// 2. Repository seeded with those identities. nil cert/L7/translator are
	// tolerated for L3/L4 policy; L7/TLS rules would need them wired.
	idmgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, nil, nil, nil, idmgr, testpolicy.NewPolicyMetricsNoop())

	// LookupFlow checks BOTH the subject and the regular SelectorCache, and the
	// constructor only seeds the regular one — so load identities into both.
	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(idMap, nil, wg)
	repo.GetSubjectSelectorCache().UpdateIdentities(idMap, nil, wg)
	wg.Wait()

	// 3. Load policies. CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy
	// convert to api.Rules (loaded together via MustAddList). Plain Kubernetes
	// NetworkPolicy takes Cilium's own k8s seam instead — ParseNetworkPolicy
	// yields policy.PolicyEntries loaded per-object via ReplaceByResource, the
	// same path the agent's policy watcher uses.
	var cnpRules policyapi.Rules
	for _, p := range req.Policies {
		kind, apiVersion, err := manifestHead(p.YAML)
		if err != nil {
			resp.Errors = append(resp.Errors, err.Error())
			continue
		}
		switch {
		case kind == "CiliumNetworkPolicy" || kind == "CiliumClusterwideNetworkPolicy":
			rs, err := parseCiliumCRD(logger, kind, p.YAML)
			if err != nil {
				resp.Errors = append(resp.Errors, err.Error())
				continue
			}
			cnpRules = append(cnpRules, rs...)
		case isK8sNetworkPolicy(kind, apiVersion, p.Flavor):
			if err := loadK8sNetworkPolicy(logger, repo, p.YAML); err != nil {
				resp.Errors = append(resp.Errors, err.Error())
			}
		case kind == "ClusterNetworkPolicy":
			if err := loadK8sClusterNetworkPolicy(logger, repo, p.YAML); err != nil {
				resp.Errors = append(resp.Errors, err.Error())
			}
		default:
			resp.Warnings = append(resp.Warnings,
				fmt.Sprintf("cilium provider: skipping manifest kind %q "+
					"(evaluated kinds: CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, k8s NetworkPolicy, ClusterNetworkPolicy)", kind))
		}
	}
	if len(cnpRules) > 0 {
		func() {
			// MustAddList panics on an invalid rule; contain it so one bad
			// policy becomes an error, not a dead engine.
			defer func() {
				if r := recover(); r != nil {
					resp.Errors = append(resp.Errors, fmt.Sprintf("cilium provider: load rules: %v", r))
				}
			}()
			repo.MustAddList(cnpRules)
		}()
	}

	// 4. Probe defaults mirror the Antrea engine (tcp/8080) so a topology with
	// no explicit probe evaluates identically across engines. LookupFlow
	// rejects a zero port/proto, so these must be non-zero.
	proto := u8proto.TCP
	if req.Protocol != "" {
		if p, err := u8proto.ParseProtocol(strings.ToUpper(req.Protocol)); err == nil {
			proto = p
		}
	}
	port := req.Port
	if port == 0 {
		port = 8080
	}

	for i, j := range api.EndpointPairs(req.Endpoints, req.MatrixPairs) {
		src, dst := req.Endpoints[i], req.Endpoints[j]
		flow := policytypes.Flow{
			From:          idents[i],
			To:            idents[j],
			Proto:         proto,
			Dport:         uint16(port),
			NamedPortsTCP: namedTCP[j],
			NamedPortsUDP: namedUDP[j],
		}
		verdict := "deny"
		if v, _, _, err := policy.LookupFlow(logger, repo, idmgr, flow); err != nil {
			resp.Warnings = append(resp.Warnings,
				fmt.Sprintf("cilium provider: %s->%s lookup: %v", src.ID, dst.ID, err))
		} else if v.Allowed() {
			verdict = "allow"
		}
		resp.Matrix[src.ID+"->"+dst.ID] = verdict
	}

	resp.Actors = make([]api.Actor, 0, len(req.Endpoints))
	for _, ep := range req.Endpoints {
		kind := ep.Role
		if kind == "" {
			kind = "workload"
		}
		resp.Actors = append(resp.Actors, api.Actor{ID: ep.ID, Kind: kind})
	}
	return resp
}

// endpointLabels builds the Cilium label set for an endpoint the way the agent
// does, all under the k8s source (what selectors compile against):
//   - the pod's own labels,
//   - io.kubernetes.pod.namespace=<ns> (scopes a namespaced CNP's endpointSelector),
//   - the namespace's labels projected as io.cilium.k8s.namespace.labels.<k>=<v>,
//     which is what a k8s NetworkPolicy namespaceSelector is compiled to match
//     (plus kubernetes.io/metadata.name, which the apiserver always sets).
func endpointLabels(ep api.Endpoint, nsLabels map[string]map[string]string) labels.Labels {
	m := make(map[string]string, len(ep.Labels)+2)
	for k, v := range ep.Labels {
		m[k] = v
	}
	if ns := endpointNamespace(ep); ns != "" {
		m[k8sConst.PodNamespaceLabel] = ns
		project := func(k, v string) { m[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v }
		project(k8sConst.LabelMetadataName, ns)
		for k, v := range nsLabels[ns] {
			project(k, v)
		}
	}
	lbls := labels.Map2Labels(m, labels.LabelSourceK8s)
	// An off-cluster peer ("the internet", a partner API) is modeled the way
	// Cilium's ipcache models any non-endpoint IP: a CIDR identity carrying the
	// host-prefix cidr label AND the reserved:world label. That makes toCIDR /
	// fromCIDR rules match it (Cilium's SelectorCache does prefix containment on
	// cidr labels — LabelArray.Has treats `cidr:1.1.1.1/32` as satisfying a
	// broader `cidr:1.0.0.0/8` selector, and a CIDR selector also requires the
	// world label) and toEntities/fromEntities: world match it too. We reuse
	// Cilium's own labels.GetCIDRLabels (the call the ipcache uses) rather than
	// reimplement the prefix math.
	//
	// In-cluster pods are deliberately NOT given these labels: a pod is not
	// "world", and whether a toCIDR that happens to cover a pod IP matches it is
	// a contested, version-dependent Cilium behaviour we don't want to assert.
	// So only endpoints the caller flags off-cluster (Role "external") get the
	// CIDR identity; every pod keeps its label identity.
	if ep.Role == "external" {
		if addr, err := netip.ParseAddr(ep.IP); err == nil {
			for k, v := range labels.GetCIDRLabels(netip.PrefixFrom(addr, addr.BitLen())) {
				lbls[k] = v
			}
		}
	}
	return lbls
}

// namedPorts maps an endpoint's declared named ports for one protocol to their
// numbers, so a rule referencing a named port resolves against the destination.
func namedPorts(ep api.Endpoint, proto string) map[string]uint16 {
	var m map[string]uint16
	for _, p := range ep.Ports {
		pp := p.Protocol
		if pp == "" {
			pp = "tcp"
		}
		if p.Name != "" && strings.EqualFold(pp, proto) {
			if m == nil {
				m = map[string]uint16{}
			}
			m[p.Name] = uint16(p.Port)
		}
	}
	return m
}

// manifestHead extracts a manifest's kind and apiVersion — enough to route it
// to the right loader without a full decode.
func manifestHead(yamlText string) (kind, apiVersion string, err error) {
	var head struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	if err := yaml.Unmarshal([]byte(yamlText), &head); err != nil {
		return "", "", fmt.Errorf("cilium provider: cannot parse manifest: %v", err)
	}
	return head.Kind, head.APIVersion, nil
}

// isK8sNetworkPolicy reports whether a manifest is an upstream Kubernetes
// NetworkPolicy (vs a Cilium CRD that shares the "NetworkPolicy" suffix).
func isK8sNetworkPolicy(kind, apiVersion, flavor string) bool {
	return kind == "NetworkPolicy" &&
		(flavor == "k8s" || strings.HasPrefix(apiVersion, "networking.k8s.io/"))
}

// parseCiliumCRD decodes a CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy
// into Cilium api.Rules via the CRD's own Parse (which sanitizes and, for the
// namespaced CNP, injects the namespace match requirement).
func parseCiliumCRD(logger *slog.Logger, kind, yamlText string) (policyapi.Rules, error) {
	switch kind {
	case "CiliumNetworkPolicy":
		var cnp ciliumv2.CiliumNetworkPolicy
		if err := yaml.Unmarshal([]byte(yamlText), &cnp); err != nil {
			return nil, fmt.Errorf("cilium provider: cannot decode CiliumNetworkPolicy: %v", err)
		}
		if cnp.Namespace == "" {
			cnp.Namespace = "default"
		}
		rules, err := cnp.Parse(logger, "")
		if err != nil {
			return nil, fmt.Errorf("cilium provider: invalid CiliumNetworkPolicy %q: %v", cnp.Name, err)
		}
		return rules, nil
	default: // CiliumClusterwideNetworkPolicy
		var ccnp ciliumv2.CiliumClusterwideNetworkPolicy
		if err := yaml.Unmarshal([]byte(yamlText), &ccnp); err != nil {
			return nil, fmt.Errorf("cilium provider: cannot decode CiliumClusterwideNetworkPolicy: %v", err)
		}
		rules, err := ccnp.Parse(logger, "")
		if err != nil {
			return nil, fmt.Errorf("cilium provider: invalid CiliumClusterwideNetworkPolicy %q: %v", ccnp.Name, err)
		}
		return rules, nil
	}
}

// loadK8sNetworkPolicy converts a plain Kubernetes NetworkPolicy through
// Cilium's own k8s.ParseNetworkPolicy (which yields policy.PolicyEntries, not
// api.Rules) and loads it via Repository.ReplaceByResource under a per-object
// resource id — mirroring how the agent's policy watcher imports it. The
// recover guards the Sanitize/insert path so one malformed policy is an error,
// not a dead engine.
func loadK8sNetworkPolicy(logger *slog.Logger, repo *policy.Repository, yamlText string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("cilium provider: load k8s NetworkPolicy: %v", r)
		}
	}()
	var np slim_networkingv1.NetworkPolicy
	if uerr := yaml.Unmarshal([]byte(yamlText), &np); uerr != nil {
		return fmt.Errorf("cilium provider: cannot decode NetworkPolicy: %v", uerr)
	}
	ns := np.Namespace
	if ns == "" {
		ns = "default"
	}
	entries, perr := k8s.ParseNetworkPolicy(logger, "", &np)
	if perr != nil {
		return fmt.Errorf("cilium provider: invalid NetworkPolicy %q: %v", np.Name, perr)
	}
	repo.ReplaceByResource(entries, ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNetpol, ns, np.Name))
	return nil
}

// loadK8sClusterNetworkPolicy converts a k8s ClusterNetworkPolicy (the NPA /
// KEP-2091 admin+baseline tiers, policy.networking.k8s.io/v1alpha2) through
// Cilium's own k8s.ParseClusterNetworkPolicy into policy.PolicyEntries and loads
// them via Repository.ReplaceByResource under ResourceKindKCNP — the same seam
// the agent's policy watcher uses (see pkg/policy/k8s/cluster_network_policy.go).
// The offline resolver honors the Admin/Baseline tier ordering and Pass verdicts
// via ruleSlice.computeTierPriorities, so no tier handling is needed here.
// ClusterNetworkPolicy is cluster-scoped, so the resource id carries no namespace.
func loadK8sClusterNetworkPolicy(logger *slog.Logger, repo *policy.Repository, yamlText string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("cilium provider: load k8s ClusterNetworkPolicy: %v", r)
		}
	}()
	var cnp policyv1alpha2.ClusterNetworkPolicy
	if uerr := yaml.Unmarshal([]byte(yamlText), &cnp); uerr != nil {
		return fmt.Errorf("cilium provider: cannot decode ClusterNetworkPolicy: %v", uerr)
	}
	entries, perr := k8s.ParseClusterNetworkPolicy(logger, "", &cnp)
	if perr != nil {
		return fmt.Errorf("cilium provider: invalid ClusterNetworkPolicy %q: %v", cnp.Name, perr)
	}
	repo.ReplaceByResource(entries, ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindKCNP, "", cnp.Name))
	return nil
}

// endpointNamespace resolves an endpoint's pod namespace, falling back to
// splitting the "<namespace>/<name>" ID when the explicit field is unset (the
// harness's canonical ID form).
func endpointNamespace(ep api.Endpoint) string {
	if ep.Namespace != "" {
		return ep.Namespace
	}
	if i := strings.IndexByte(ep.ID, '/'); i >= 0 {
		return ep.ID[:i]
	}
	return ""
}
