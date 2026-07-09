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
	"strings"

	"sigs.k8s.io/yaml"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	k8s "github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"

	"github.com/frozenprocess/telepathy/api"
)

// firstIdentity is where we start allocating numeric security identities for the
// request's workloads. Anything below identity.MinimalNumericIdentity is
// reserved (host, world, …); the k8s policy tests seed their own pods from 1000,
// so we do the same — the exact values are arbitrary, they only need to be
// distinct and above the reserved range.
const firstIdentity = identity.NumericIdentity(1000)

// model is the resolved policy state the evaluator drives: Cilium's real policy
// Repository (rules + SelectorCache seeded with every workload's identity) plus
// the per-endpoint identity map the verdict lookup keys off. Selector
// resolution, identity distillation, and the {identity,port,proto}->verdict
// table are all Cilium's own code (pkg/policy); harness.go only feeds it.
type model struct {
	logger   *slog.Logger
	repo     *policy.Repository
	idMgr    identitymanager.IDManager
	ids      map[string]*identity.Identity // endpoint ID -> its security identity
	warnings []string
	errors   []string
}

// build turns req's topology into Cilium security identities, constructs a
// policy Repository seeded with them, and loads every parsed Kubernetes
// NetworkPolicy as Cilium rules. Mirrors pkg/k8s's testNewPolicyRepository +
// TestNetworkPolicyExamples wiring, driven from telepathy's Request instead of
// test literals.
func build(req api.Request) model {
	// ponytail: discard Cilium's internal logs. The engine's own output is the
	// JSON Response on stdout; slog would corrupt it, so send it to stderr-free
	// io.Discard. Bump to os.Stderr when debugging a verdict.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	nsLabels := map[string]map[string]string{}
	for _, ns := range req.Namespaces {
		nsLabels[ns.Name] = ns.Labels
	}

	m := model{logger: logger, ids: map[string]*identity.Identity{}}

	// One security identity per namespaced workload, built from the same label
	// set Cilium's agent would derive: the pod namespace, the pod's own labels,
	// and the pod namespace's labels (io.cilium.k8s.namespace.labels.* prefix).
	idMap := identity.IdentityMap{}
	next := firstIdentity
	for _, ep := range req.Endpoints {
		ns := endpointNamespace(ep)
		if ns == "" {
			// Non-namespaced endpoints (external destinations / hosts) have no
			// pod identity; they are handled as world/CIDR peers, not yet
			// modelled here. See eval.go.
			continue
		}
		lbls := podLabels(ns, ep.Labels, nsLabels[ns])
		next++
		id := identity.NewIdentity(next, lbls.Labels())
		m.ids[ep.ID] = id
		idMap[id.ID] = id.LabelArray
	}

	m.idMgr = identitymanager.NewIDManager(logger)
	m.repo = policy.NewPolicyRepository(logger, idMap, nil, nil, m.idMgr, testpolicy.NewPolicyMetricsNoop())
	m.repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

	for _, p := range req.Policies {
		np, kind, err := parseK8sNetworkPolicy(p)
		switch {
		case err != nil:
			m.errors = append(m.errors, err.Error())
		case np != nil:
			entries, err := k8s.ParseNetworkPolicy(logger, cmtypes.PolicyAnyCluster, np)
			if err != nil {
				m.errors = append(m.errors, fmt.Sprintf("cilium provider: parse %s/%s: %v", np.Namespace, np.Name, err))
				continue
			}
			m.repo.MustAddPolicyEntries(entries)
		default:
			m.warnings = append(m.warnings,
				fmt.Sprintf("cilium provider: skipping unsupported manifest kind %q "+
					"(only Kubernetes NetworkPolicy is evaluated today)", kind))
		}
	}
	return m
}

// podLabels builds the Cilium label set for a workload, matching how the agent
// derives identity labels from a Pod: the namespace, the pod's own labels, and
// the namespace's labels under the io.cilium.k8s.namespace.labels.* prefix (so
// namespaceSelector rules resolve). All in the k8s label source.
func podLabels(namespace string, podLabels, nsLabels map[string]string) labels.LabelArray {
	lbls := labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, namespace, labels.LabelSourceK8s),
	}
	for k, v := range podLabels {
		lbls = append(lbls, labels.NewLabel(k, v, labels.LabelSourceK8s))
	}
	for k, v := range nsLabels {
		lbls = append(lbls, labels.NewLabel("io.cilium.k8s.namespace.labels."+k, v, labels.LabelSourceK8s))
	}
	return lbls.Sort()
}

// parseK8sNetworkPolicy decodes a manifest into Cilium's slim NetworkPolicy when
// it is a Kubernetes NetworkPolicy. Returns (nil, kind, nil) for any other kind
// so the caller surfaces a skip warning, and (nil, kind, err) only on malformed
// input. Mirrors the Antrea engine's parser, targeting the slim type
// ParseNetworkPolicy expects.
func parseK8sNetworkPolicy(p api.PolicyInput) (*slim_networkingv1.NetworkPolicy, string, error) {
	var head struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	if err := yaml.Unmarshal([]byte(p.YAML), &head); err != nil {
		return nil, "", fmt.Errorf("cilium provider: cannot parse manifest: %v", err)
	}
	isK8sNP := head.Kind == "NetworkPolicy" &&
		(p.Flavor == "k8s" || strings.HasPrefix(head.APIVersion, "networking.k8s.io/"))
	if !isK8sNP {
		return nil, head.Kind, nil
	}
	var np slim_networkingv1.NetworkPolicy
	if err := yaml.Unmarshal([]byte(p.YAML), &np); err != nil {
		return nil, head.Kind, fmt.Errorf("cilium provider: cannot decode NetworkPolicy: %v", err)
	}
	if np.Namespace == "" {
		np.Namespace = "default"
	}
	return &np, head.Kind, nil
}
