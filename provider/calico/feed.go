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

package calico

import (
	"errors"
	"fmt"
	"os"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	networkingv1 "k8s.io/api/networking/v1"
	clusternetpol "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// feedPolicy parses one policy YAML and routes it through the appropriate
// libcalico-go updateprocessor before sending the resulting backend KVPairs
// into the calc graph via `send`. evaluateStaged controls whether
// Staged{Global}NetworkPolicy and StagedKubernetesNetworkPolicy participate;
// when false (the default) staged policies are silently skipped, matching
// Calico's runtime "staged is inactive until promoted" behaviour.
//
// icmp carries the probe's ICMP type/code when the caller set them on the
// Request; when non-nil, rules whose icmp/notICMP matchers contradict the
// probe are dropped from the apiv3 spec before it reaches the calc graph.
// The filter is a no-op for non-ICMP probes and for callers that leave the
// fields unset (preserves the engine's pre-extension "ignore icmp.type/code"
// behaviour, so existing datasets keep matching the cluster oracle).
func feedPolicy(send func(model.Key, any), p PolicyInput, evaluateStaged bool, icmp *icmpProbe) error {
	var tm struct {
		Kind string `json:"kind"`
	}
	if err := yaml.Unmarshal([]byte(p.YAML), &tm); err != nil {
		return fmt.Errorf("parse kind: %w", err)
	}
	switch tm.Kind {
	case "NetworkPolicy":
		if p.Flavor == "k8s" {
			var np networkingv1.NetworkPolicy
			if err := yaml.Unmarshal([]byte(p.YAML), &np); err != nil {
				return fmt.Errorf("parse k8s NetworkPolicy: %w", err)
			}
			// Converts to a Calico v3 NetworkPolicy (Kind=KubernetesNetworkPolicy);
			// it still needs the same updateprocessor to become a backend model.Policy.
			kvp, err := conversion.NewConverter().K8sNetworkPolicyToCalico(&np)
			if err != nil {
				return fmt.Errorf("convert k8s NetworkPolicy: %w", err)
			}
			applyICMPFilter(kvp.Value, icmp)
			return process(send, updateprocessors.NewNetworkPolicyUpdateProcessor(model.KindKubernetesNetworkPolicy),
				kvp.Key, kvp.Value)
		}
		var cnp apiv3.NetworkPolicy
		if err := yaml.Unmarshal([]byte(p.YAML), &cnp); err != nil {
			return fmt.Errorf("parse Calico NetworkPolicy: %w", err)
		}
		defaultPolicyTypes(&cnp.Spec.Types, cnp.Spec.Ingress, cnp.Spec.Egress)
		applyICMPFilter(&cnp, icmp)
		return process(send, updateprocessors.NewNetworkPolicyUpdateProcessor(apiv3.KindNetworkPolicy),
			model.ResourceKey{Kind: apiv3.KindNetworkPolicy, Name: cnp.Name, Namespace: cnp.Namespace}, &cnp)
	case "GlobalNetworkPolicy":
		var gnp apiv3.GlobalNetworkPolicy
		if err := yaml.Unmarshal([]byte(p.YAML), &gnp); err != nil {
			return fmt.Errorf("parse GlobalNetworkPolicy: %w", err)
		}
		defaultPolicyTypes(&gnp.Spec.Types, gnp.Spec.Ingress, gnp.Spec.Egress)
		applyICMPFilter(&gnp, icmp)
		return process(send, updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(apiv3.KindGlobalNetworkPolicy),
			model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: gnp.Name}, &gnp)
	case "Tier":
		// User-defined Calico Tier. The engine pre-creates the three reserved
		// tiers (default/kube-admin/kube-baseline) at startup; this branch
		// lets a testcase add arbitrary additional tiers (e.g. "security" at
		// order 100) so policies that set `spec.tier: <name>` resolve.
		var tier apiv3.Tier
		if err := yaml.Unmarshal([]byte(p.YAML), &tier); err != nil {
			return fmt.Errorf("parse Tier: %w", err)
		}
		return process(send, updateprocessors.NewTierUpdateProcessor(),
			model.ResourceKey{Kind: apiv3.KindTier, Name: tier.Name}, &tier)
	case "ClusterNetworkPolicy":
		// v1alpha2 policy.networking.k8s.io ClusterNetworkPolicy (NPA / KEP-2091
		// successor that replaces v1alpha1 ANP+BANP). libcalico-go converts it
		// to a Calico GlobalNetworkPolicy tagged with
		// KindKubernetesClusterNetworkPolicy and slots it into the kube-admin
		// or kube-baseline tier per Spec.Tier.
		var kcnp clusternetpol.ClusterNetworkPolicy
		if err := yaml.Unmarshal([]byte(p.YAML), &kcnp); err != nil {
			return fmt.Errorf("parse ClusterNetworkPolicy: %w", err)
		}
		kvp, err := conversion.NewConverter().K8sClusterNetworkPolicyToCalico(&kcnp)
		// ErrorClusterNetworkPolicyConversion means "I dropped some rules but
		// the rest is fine" — Calico's in-cluster client swallows it; we
		// surface to stderr but keep going so a partially-valid policy still
		// feeds the graph.
		var partial cerrors.ErrorClusterNetworkPolicyConversion
		if err != nil && !errors.As(err, &partial) {
			return fmt.Errorf("convert ClusterNetworkPolicy: %w", err)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "ClusterNetworkPolicy %q: partial conversion: %v\n", kcnp.Name, err)
		}
		if kvp == nil || kvp.Value == nil {
			return fmt.Errorf("ClusterNetworkPolicy %q: converter returned no value (malformed tier/subject)", kcnp.Name)
		}
		applyICMPFilter(kvp.Value, icmp)
		return process(send,
			updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(model.KindKubernetesClusterNetworkPolicy),
			kvp.Key, kvp.Value)
	case "NetworkSet":
		var ns apiv3.NetworkSet
		if err := yaml.Unmarshal([]byte(p.YAML), &ns); err != nil {
			return fmt.Errorf("parse NetworkSet: %w", err)
		}
		return process(send, updateprocessors.NewNetworkSetUpdateProcessor(),
			model.ResourceKey{Kind: apiv3.KindNetworkSet, Name: ns.Name, Namespace: ns.Namespace}, &ns)
	case "GlobalNetworkSet":
		var gns apiv3.GlobalNetworkSet
		if err := yaml.Unmarshal([]byte(p.YAML), &gns); err != nil {
			return fmt.Errorf("parse GlobalNetworkSet: %w", err)
		}
		return process(send, updateprocessors.NewGlobalNetworkSetUpdateProcessor(),
			model.ResourceKey{Kind: apiv3.KindGlobalNetworkSet, Name: gns.Name}, &gns)
	case "HostEndpoint":
		// HostEndpoints fed via Request.Policies are convenience-equivalent to
		// Request.HostEndpoints — both reach the same updateprocessor. They
		// become rows/cols in the connectivity matrix (id "host/<Name>") and
		// their applyOnForward / preDNAT / doNotTrack tiers gate flows on
		// their Node via eval.go's overlays. Use Request.HostEndpoints when
		// you need the typed struct (Node, ExpectedIPs) without YAML.
		//
		// We rewrite Spec.Node to the engine's hostname so the calc graph's
		// endpointHostnameFilter accepts the HEP as local. The HEP-to-node
		// association for the forward/preDNAT overlays only works when the
		// caller uses Request.HostEndpoints (the struct carries Node); when
		// passed via YAML there's no way to plumb that through to the matrix
		// loop, so YAML HEPs apply universally (Node defaults to "" everywhere).
		var hep apiv3.HostEndpoint
		if err := yaml.Unmarshal([]byte(p.YAML), &hep); err != nil {
			return fmt.Errorf("parse HostEndpoint: %w", err)
		}
		hep.Spec.Node = hostname
		return process(send, updateprocessors.NewHostEndpointUpdateProcessor(),
			model.ResourceKey{Kind: apiv3.KindHostEndpoint, Name: hep.Name}, &hep)
	case "StagedNetworkPolicy":
		if !evaluateStaged {
			return nil
		}
		var snp apiv3.StagedNetworkPolicy
		if err := yaml.Unmarshal([]byte(p.YAML), &snp); err != nil {
			return fmt.Errorf("parse StagedNetworkPolicy: %w", err)
		}
		defaultPolicyTypes(&snp.Spec.Types, snp.Spec.Ingress, snp.Spec.Egress)
		applyICMPFilter(&snp, icmp)
		return process(send, updateprocessors.NewStagedNetworkPolicyUpdateProcessor(),
			model.ResourceKey{Kind: apiv3.KindStagedNetworkPolicy, Name: snp.Name, Namespace: snp.Namespace}, &snp)
	case "StagedGlobalNetworkPolicy":
		if !evaluateStaged {
			return nil
		}
		var sgnp apiv3.StagedGlobalNetworkPolicy
		if err := yaml.Unmarshal([]byte(p.YAML), &sgnp); err != nil {
			return fmt.Errorf("parse StagedGlobalNetworkPolicy: %w", err)
		}
		defaultPolicyTypes(&sgnp.Spec.Types, sgnp.Spec.Ingress, sgnp.Spec.Egress)
		applyICMPFilter(&sgnp, icmp)
		return process(send, updateprocessors.NewStagedGlobalNetworkPolicyUpdateProcessor(),
			model.ResourceKey{Kind: apiv3.KindStagedGlobalNetworkPolicy, Name: sgnp.Name}, &sgnp)
	case "StagedKubernetesNetworkPolicy":
		if !evaluateStaged {
			return nil
		}
		var skp apiv3.StagedKubernetesNetworkPolicy
		if err := yaml.Unmarshal([]byte(p.YAML), &skp); err != nil {
			return fmt.Errorf("parse StagedKubernetesNetworkPolicy: %w", err)
		}
		return process(send, updateprocessors.NewStagedKubernetesNetworkPolicyUpdateProcessor(),
			model.ResourceKey{Kind: apiv3.KindStagedKubernetesNetworkPolicy, Name: skp.Name, Namespace: skp.Namespace}, &skp)
	default:
		return fmt.Errorf("unsupported policy kind %q", tm.Kind)
	}
}

// defaultPolicyTypes mirrors the Calico API-server write-path defaulting that
// the engine bypasses by feeding YAML straight into the updateprocessor: an
// unset Types is inferred from which rule lists are present ([Ingress] when
// there are no egress rules, [Egress] when egress-only, both when both).
// Without this, Felix's back-compat path (felix/calc/policy_sorter.go) treats
// empty Types as Ingress+Egress, diverging from a live cluster. Runs before
// applyICMPFilter so the inference sees the rules as written, like the API
// server would.
func defaultPolicyTypes(types *[]apiv3.PolicyType, ingress, egress []apiv3.Rule) {
	if len(*types) != 0 {
		return
	}
	switch {
	case len(egress) == 0:
		*types = []apiv3.PolicyType{apiv3.PolicyTypeIngress}
	case len(ingress) == 0:
		*types = []apiv3.PolicyType{apiv3.PolicyTypeEgress}
	default:
		*types = []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress}
	}
}

func process(send func(model.Key, any), up watchersyncer.SyncerUpdateProcessor, key model.Key, value any) error {
	kvps, err := up.Process(&model.KVPair{Key: key, Value: value})
	if err != nil {
		return fmt.Errorf("updateprocessor: %w", err)
	}
	for _, kvp := range kvps {
		if kvp.Value != nil {
			send(kvp.Key, kvp.Value)
		}
	}
	return nil
}
