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
	"strings"

	"github.com/cilium/cilium/pkg/policy"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/frozenprocess/telepathy/api"
)

// evaluate computes the pod-to-pod connectivity matrix for req. Selector
// resolution and the verdict are Cilium's own: build() constructs a real
// pkg/policy Repository, and policy.LookupFlow resolves each flow's egress
// (source) and ingress (destination) policy through the SelectorCache and
// EndpointPolicy map — a flow is allowed only if neither side denies it, the
// same two-sided model the Calico and Antrea engines use.
func evaluate(req api.Request) api.Response {
	m := build(req)

	resp := api.Response{Matrix: map[string]string{}}
	resp.Warnings = m.warnings
	resp.Errors = m.errors

	proto := u8proto.TCP
	if strings.EqualFold(req.Protocol, "udp") {
		proto = u8proto.UDP
	}
	port := uint16(req.Port)
	if port == 0 {
		port = 8080
	}

	// One-shot note if any external/non-namespaced endpoints are present: they
	// have no security identity yet, so pairs touching them can't be resolved
	// through pkg/policy. ponytail: model these as world/CIDR peers next.
	if len(m.ids) < len(req.Endpoints) {
		resp.Warnings = append(resp.Warnings,
			"cilium provider: non-namespaced endpoints have no identity yet; "+
				"flows to/from them are reported deny (world/CIDR peers not modelled)")
	}

	for _, src := range req.Endpoints {
		for _, dst := range req.Endpoints {
			if src.ID == dst.ID {
				continue
			}
			resp.Matrix[src.ID+"->"+dst.ID] = m.verdict(src, dst, proto, port)
		}
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

// verdict resolves one src->dst:port flow through Cilium's policy engine,
// returning "allow" or "deny". Pairs involving an endpoint with no security
// identity (external/non-namespaced) can't be looked up and default to deny.
func (m model) verdict(src, dst api.Endpoint, proto u8proto.U8proto, port uint16) string {
	from, ok := m.ids[src.ID]
	if !ok {
		return "deny"
	}
	to, ok := m.ids[dst.ID]
	if !ok {
		return "deny"
	}
	flow := policytypes.Flow{From: from, To: to, Proto: proto, Dport: port}
	verdict, _, _, err := policy.LookupFlow(m.logger, m.repo, m.idMgr, flow)
	if err != nil || !verdict.Allowed() {
		return "deny"
	}
	return "allow"
}

// endpointNamespace resolves an endpoint's namespace, falling back to splitting
// the "<namespace>/<name>" ID. A non-namespaced endpoint (external destination
// / host) yields "" and gets no security identity.
func endpointNamespace(ep api.Endpoint) string {
	if ep.Namespace != "" {
		return ep.Namespace
	}
	if i := strings.IndexByte(ep.ID, '/'); i >= 0 {
		return ep.ID[:i]
	}
	return ""
}
