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
	"net"
	"strings"

	"github.com/frozenprocess/telepathy/api"
)

// evaluate computes the pod-to-pod connectivity matrix for req. Selector
// resolution is done by Antrea's grouping engine (see build); here we apply
// Kubernetes NetworkPolicy semantics: a flow src->dst:port is allowed iff it
// clears BOTH dst's ingress and src's egress (how a real packet must pass),
// mirroring the Calico provider's two-sided model.
func evaluate(req api.Request) api.Response {
	m := build(req)

	resp := api.Response{Matrix: map[string]string{}}
	resp.Warnings = m.warnings
	resp.Errors = m.errors

	proto := req.Protocol
	if proto == "" {
		proto = "tcp"
	}
	port := req.Port
	if port == 0 {
		port = 8080
	}

	for _, src := range req.Endpoints {
		for _, dst := range req.Endpoints {
			if src.ID == dst.ID {
				continue
			}
			verdict := "deny"
			if m.ingressAllows(dst, src, proto, port) && m.egressAllows(src, dst, proto, port) {
				verdict = "allow"
			}
			resp.Matrix[src.ID+"->"+dst.ID] = verdict
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

// ingressAllows reports whether dst accepts traffic from src at (proto, port).
// If dst is selected by no Ingress policy it is not isolated and everything is
// allowed; otherwise some ingress rule of an applied policy must match.
func (m model) ingressAllows(dst, src api.Endpoint, proto string, port int) bool {
	dstKey := podKey(dst)
	isolated, matched := false, false
	for _, p := range m.policies {
		if !p.ingressIsolate || !p.appliedTo[dstKey] {
			continue
		}
		isolated = true
		for _, rule := range p.ingress {
			if rule.matches(src, proto, port, dst) {
				matched = true
			}
		}
	}
	return !isolated || matched
}

// egressAllows is the mirror of ingressAllows for src's egress policies. The
// matched port is the destination's port, so named ports resolve against dst.
func (m model) egressAllows(src, dst api.Endpoint, proto string, port int) bool {
	srcKey := podKey(src)
	isolated, matched := false, false
	for _, p := range m.policies {
		if !p.egressIsolate || !p.appliedTo[srcKey] {
			continue
		}
		isolated = true
		for _, rule := range p.egress {
			if rule.matches(dst, proto, port, dst) {
				matched = true
			}
		}
	}
	return !isolated || matched
}

// matches reports whether a rule admits peer at (proto, port). portOwner is the
// endpoint that owns the matched port (always the destination) for named-port
// resolution.
func (r resolvedRule) matches(peer api.Endpoint, proto string, port int, portOwner api.Endpoint) bool {
	return r.peerMatches(peer) && r.portMatches(proto, port, portOwner)
}

func (r resolvedRule) peerMatches(peer api.Endpoint) bool {
	if r.matchAllPeers {
		return true
	}
	if r.peerPods[podKey(peer)] {
		return true
	}
	if peer.IP != "" {
		ip := net.ParseIP(peer.IP)
		for _, blk := range r.ipBlocks {
			if blk.contains(ip) {
				return true
			}
		}
	}
	return false
}

func (r resolvedRule) portMatches(proto string, port int, owner api.Endpoint) bool {
	if len(r.ports) == 0 {
		return true
	}
	for _, ps := range r.ports {
		if ps.proto != strings.ToLower(proto) {
			continue
		}
		if ps.named != "" {
			if resolveNamed(owner, ps.named, proto) == port {
				return true
			}
			continue
		}
		if ps.port == -1 {
			return true // all ports of this protocol
		}
		if port >= ps.port && port <= ps.endPort {
			return true
		}
	}
	return false
}

func (b resolvedIPBlock) contains(ip net.IP) bool {
	if ip == nil || b.cidr == nil || !b.cidr.Contains(ip) {
		return false
	}
	for _, ex := range b.except {
		if ex.Contains(ip) {
			return false
		}
	}
	return true
}

// resolveNamed maps a named port to its number using the endpoint's declared
// ports for the protocol, or -1 when unresolved.
func resolveNamed(ep api.Endpoint, name, proto string) int {
	for _, p := range ep.Ports {
		pp := p.Protocol
		if pp == "" {
			pp = "tcp"
		}
		if p.Name == name && strings.EqualFold(pp, proto) {
			return p.Port
		}
	}
	return -1
}

// podKey is an endpoint's pod identity ("namespace/name"), matching the keys
// build resolves selectors into.
func podKey(ep api.Endpoint) string {
	return endpointNamespace(ep) + "/" + endpointName(ep)
}

// endpointNamespace / endpointName resolve an endpoint's pod identity, falling
// back to splitting the "<namespace>/<name>" ID when the explicit fields are
// unset. A non-namespaced endpoint (external destination / host) yields a key
// no pod selector will match, so it is never policy-isolated.
func endpointNamespace(ep api.Endpoint) string {
	if ep.Namespace != "" {
		return ep.Namespace
	}
	if i := strings.IndexByte(ep.ID, '/'); i >= 0 {
		return ep.ID[:i]
	}
	return ""
}

func endpointName(ep api.Endpoint) string {
	if ep.Name != "" {
		return ep.Name
	}
	if i := strings.IndexByte(ep.ID, '/'); i >= 0 {
		return ep.ID[i+1:]
	}
	return ep.ID
}
