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
	"fmt"
	"net"
	"os"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	libnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const hostname = "telepathy-node"

// Evaluate runs one connectivity sweep. It builds a fresh calc graph from the
// (Endpoints, Namespaces, Policies, …) tuple in req, then probes every
// ordered pod pair at (req.Protocol, req.Port), returning a Response whose
// Matrix maps "src.ID->dst.ID" to "allow" or "deny".
//
// Port defaults to 8080 and Protocol to "tcp" when zero/empty; SrcPort
// defaults to 12345 when zero. HTTP method/path default to nil. ICMP
// type/code default to nil too; when the caller sets either, rules whose
// icmp/notICMP matchers contradict the probe are filtered out of the
// policies before they reach the calc graph (see filterRulesByICMP in feed.go
// for the rationale — the upstream app-policy/checker we reuse for
// rule walking ignores these fields, so we do the matching at feed time).
//
// Per-policy parse/conversion errors are collected in Response.Errors rather
// than failing the call. Lint findings (unsupported features) go to
// Response.Warnings; with req.StrictLint=true they become errors.
func Evaluate(req Request) Response {
	if req.Port == 0 {
		req.Port = 8080
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if req.SrcPort == 0 {
		req.SrcPort = 12345
	}

	resp := Response{Matrix: map[string]string{}}

	// Pull any pasted ServiceAccount/Service manifests out of Policies into the
	// typed slices before anything reads the Request (lint, buildGraph, and the
	// service-column builder below all consume it). See applyInlineResources.
	var inlineErrs []string
	req, inlineErrs = applyInlineResources(req)
	resp.Errors = append(resp.Errors, inlineErrs...)

	// Lint policies up-front so warnings appear even if downstream conversion
	// fails. StrictLint promotes warnings to errors and short-circuits.
	if w, e := lintPolicies(req); len(w)+len(e) > 0 {
		if req.StrictLint {
			resp.Errors = append(resp.Errors, e...)
			resp.Errors = append(resp.Errors, w...)
			return resp
		}
		resp.Warnings = append(resp.Warnings, w...)
		resp.Errors = append(resp.Errors, e...)
	}

	// Build Felix's calc graph and feed it the topology + policies. The ICMP
	// probe (when the Request enables it) filters contradictory icmp rules at
	// feed time — see icmp.go. Everything heavy lives in buildGraph (shared
	// with RenderIptables); here we just collect its warnings/errors and the
	// per-endpoint proto the checker walks.
	icmp := newICMPProbe(req)
	g := buildGraph(req, icmp)
	resp.Warnings = append(resp.Warnings, g.warnings...)
	resp.Errors = append(resp.Errors, g.errors...)
	store, wepByID, hepByName := g.store, g.wepByID, g.hepByName

	if os.Getenv("POLICY_ENGINE_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "DEBUG weps=%d policies=%d profiles=%d ipsets=%d\n",
			len(wepByID), len(store.PolicyByID), len(store.ProfileByID), len(store.IPSetByID))
		for id, s := range store.IPSetByID {
			fmt.Fprintf(os.Stderr, "  ipset %s members=%v\n", id, s.Members())
		}
		for id, w := range wepByID {
			fmt.Fprintf(os.Stderr, "  wep %s profiles=%v tiers=%d\n", id, w.GetProfileIds(), len(w.GetTiers()))
			for _, t := range w.GetTiers() {
				fmt.Fprintf(os.Stderr, "    tier=%s default=%s ingress=%d egress=%d\n",
					t.GetName(), t.GetDefaultAction(), len(t.GetIngressPolicies()), len(t.GetEgressPolicies()))
			}
		}
	}

	// Build the unified "actor" list: workloads + HEPs. Each actor carries the
	// per-tier-flavor synthetic proto.WorkloadEndpoint that checker.Evaluate
	// walks (the checker only reads ep.Tiers + ep.ProfileIds, so we get
	// applyOnForward / preDNAT / doNotTrack by swapping which tier list lives
	// in the synth WEP's Tiers field — Calico's calc graph already split them
	// out on the proto.HostEndpoint we captured above).
	actors := buildActors(req, wepByID, hepByName)
	for _, w := range actors.warnings {
		resp.Warnings = append(resp.Warnings, w)
	}

	mkFlow := flowFactory(req)

	for _, src := range actors.list {
		for _, dst := range actors.list {
			if src.id == dst.id {
				continue
			}
			allow, _ := evalFlow(store, src, dst, mkFlow(src, dst), mkFlow(dst, src), actors.hepsByNode)

			res := "deny"
			if allow {
				res = "allow"
			}
			resp.Matrix[src.id+"->"+dst.id] = res
		}
	}

	addServiceColumns(&resp, req, actors)
	buildActorReport(&resp, actors)
	return resp
}

// flowFactory returns a builder for the per-pair flow probe from the Request's
// single probe (protocol/port/http). Hoisted out of Evaluate so ResolveTierMatches
// can drive the identical per-flow evaluation.
func flowFactory(req Request) func(src, dst *actor) *flow {
	protoNum := protocolNumber(req.Protocol)
	dstPort := req.Port
	if !protocolHasL4Ports(protoNum) {
		dstPort = 0
	}
	httpMethod := strPtr(req.HTTPMethod)
	httpPath := strPtr(req.HTTPPath)
	return func(src, dst *actor) *flow {
		return &flow{
			srcIP:      src.ip,
			dstIP:      dst.ip,
			srcPort:    req.SrcPort,
			dstPort:    dstPort,
			protocol:   protoNum,
			httpMethod: httpMethod,
			httpPath:   httpPath,
		}
	}
}

// evalFlow runs the full per-flow policy walk for one src→dst pair and returns
// the allow/deny verdict plus the set of tier names whose END-OF-TIER default
// action was reached by any of the flow's evaluations. Reaching a tier's
// end-of-tier action is a "partial match": the tier's policies select the
// endpoint (so the tier is in its path) but no rule in the tier decided this
// flow, so it falls through to the tier's default action. The checker records
// that as a RuleID with Index == RuleIndexTierDefaultAction (see
// app-policy/checker), which IsTierDefaultActionRule() detects.
//
// This is the single source of truth for the matrix (Evaluate ignores the
// end-of-tier set) and for ResolveTierMatches' end-of-tier flow accounting, so
// the two can never diverge on the overlay logic below.
func evalFlow(store *policystore.PolicyStore, src, dst *actor, f, rev *flow, hepsByNode map[string][]*actor) (bool, map[string]bool) {
	eot := map[string]bool{}
	// eval wraps checker.Evaluate: same bool verdict as before, but it also
	// harvests any end-of-tier actions the walk hit into eot.
	walk := func(dir rules.RuleDir, ep *proto.WorkloadEndpoint, fl *flow) bool {
		trace := checker.Evaluate(dir, store, ep, fl)
		for _, rid := range trace {
			// Count only real policy tiers reaching their end-of-tier action; the
			// checker emits the same marker for a profile fall-through (Kind
			// Profile, Tier "__PROFILE__"), which isn't a tier in the tier view.
			if rid != nil && rid.IsTierDefaultActionRule() && rid.Kind != apiv3.KindProfile {
				eot[rid.Tier] = true
			}
		}
		return verdict(trace)
	}

	// Terminating-traffic hook: standard egress(src) AND ingress(dst). For HEPs
	// this uses hep.Tiers (policies WITHOUT doNotTrack / preDNAT / applyOnForward).
	// Unpoliced (a node with no HEP) short-circuits: no policy, so no evaluation
	// and no end-of-tier reach.
	egressOK := src.unpoliced || walk(rules.RuleDirEgress, src.normalWEP(), f)
	ingressOK := dst.unpoliced || walk(rules.RuleDirIngress, dst.normalWEP(), f)
	allow := egressOK && ingressOK

	// applyOnForward overlay: HEPs on src.node / dst.node carrying a forward
	// policy in the relevant direction. The direction guard (forwardTierHas)
	// leaves the unspecified direction default-ALLOW, matching Calico.
	for _, h := range hepsByNode[src.node] {
		if h.id == src.id || !forwardTierHas(h.hep, false) {
			continue
		}
		if !walk(rules.RuleDirEgress, h.forwardWEP(), f) {
			allow = false
		}
	}
	for _, h := range hepsByNode[dst.node] {
		if h.id == dst.id || !forwardTierHas(h.hep, true) {
			continue
		}
		if !walk(rules.RuleDirIngress, h.forwardWEP(), f) {
			allow = false
		}
	}

	// preDNAT overlay: HEPs on the destination node with PreDnatTiers gate
	// ingress before kube-proxy DNAT.
	for _, h := range hepsByNode[dst.node] {
		if h.id == dst.id || len(h.hep.GetPreDnatTiers()) == 0 {
			continue
		}
		if !walk(rules.RuleDirIngress, h.preDnatWEP(), f) {
			allow = false
		}
	}

	// doNotTrack overlay: applies only when the HEP itself is src or dst.
	// Untracked traffic has no conntrack, so the reply leg traverses the same
	// rules — model that by requiring the reverse-direction evaluation to allow.
	if src.kind == actorHEP && len(src.hep.GetUntrackedTiers()) > 0 {
		fwd := walk(rules.RuleDirEgress, src.untrackedWEP(), f)
		rvs := walk(rules.RuleDirIngress, src.untrackedWEP(), rev)
		if !(fwd && rvs) {
			allow = false
		}
	}
	if dst.kind == actorHEP && len(dst.hep.GetUntrackedTiers()) > 0 {
		fwd := walk(rules.RuleDirIngress, dst.untrackedWEP(), f)
		rvs := walk(rules.RuleDirEgress, dst.untrackedWEP(), rev)
		if !(fwd && rvs) {
			allow = false
		}
	}

	return allow, eot
}

// actorKindString maps an actor to its Response.Actor Kind. HEPs are always
// "hep"; workload actors take their Kind from the caller-supplied Role (empty
// → "workload"), the only way to tell an external destination apart from an
// unpoliced host since both are unpoliced WEPs.
func actorKindString(a *actor) string {
	if a.kind == actorHEP {
		return "hep"
	}
	switch a.role {
	case "external":
		return "external"
	case "host":
		return "host-unpoliced"
	default:
		return "workload"
	}
}

// buildActorReport fills resp.Actors: one typed entry per matrix row/col, in
// matrix order, plus each actor's internet-egress posture for this probe (allow
// if it reaches any external actor, deny if none, "" when there are no externals
// or the actor is itself external). Read-only over resp.Matrix — must run after
// the matrix loop.
func buildActorReport(resp *Response, actors actorBundle) {
	var externals []*actor
	for _, a := range actors.list {
		if actorKindString(a) == "external" {
			externals = append(externals, a)
		}
	}
	for _, a := range actors.list {
		kind := actorKindString(a)
		internet := ""
		if kind != "external" && len(externals) > 0 {
			internet = "deny"
			for _, e := range externals {
				if resp.Matrix[a.id+"->"+e.id] == "allow" {
					internet = "allow"
					break
				}
			}
		}
		resp.Actors = append(resp.Actors, Actor{
			ID:       a.id,
			Kind:     kind,
			Node:     a.node,
			Internet: internet,
		})
	}
}

// addServiceColumns adds a destination-only "svc/<ns>/<name>" column per
// Request.Service. A ClusterIP is virtual: kube-proxy DNATs a connection to it
// onto one of the Service's backend pods, so the Service is reachable iff AT
// LEAST ONE backend pod is reachable. We model that as the OR, over the
// Service's backend endpoints, of the already-computed src->backend verdict in
// the pod-to-pod matrix.
//
// This reuses the main loop's verdicts rather than re-evaluating: the calc
// graph resolves `destination.services` rules against the backend pod IPs (via
// the Service IPSet built from the EndpointSlice), so src->backend already
// reflects any service-selector policy. The column is what makes the engine
// matrix comparable to a cluster oracle that dials the ClusterIP, and gives
// testcases a single cell to assert "src can reach the Service".
//
// Services are dst-only — they never originate traffic, so no svc-> rows are
// emitted. Backends are resolved from an explicit matching EndpointSlice when
// present, else auto-derived from the Service's Selector (same logic
// feedExtraResources uses to populate the calc graph). A literal rule match on
// the ClusterIP itself (e.g. destination.nets:[<clusterIP>/32]) is NOT modelled
// — that's not how kube-proxy'd traffic is typically policed; supply the
// Service selector instead.
func addServiceColumns(resp *Response, req Request, actors actorBundle) {
	if len(req.Services) == 0 {
		return
	}
	ipToID := map[string]string{}
	for _, ep := range req.Endpoints {
		if ep.IP != "" {
			ipToID[ep.IP] = ep.ID
		}
	}
	for _, svc := range req.Services {
		backends := serviceBackendIDs(svc, req, ipToID)
		col := "svc/" + svc.Namespace + "/" + svc.Name
		for _, src := range actors.list {
			allow := false
			for _, b := range backends {
				// A pod that itself backs the Service can reach it: the flow
				// hairpins to the local pod, so at least one endpoint (itself)
				// is trivially reachable. Otherwise OR the pod-to-pod verdict.
				if b == src.id || resp.Matrix[src.id+"->"+b] == "allow" {
					allow = true
					break
				}
			}
			res := "deny"
			if allow {
				res = "allow"
			}
			resp.Matrix[src.id+"->"+col] = res
		}
	}
}

// serviceBackendIDs resolves a Service to the endpoint IDs of its backend pods:
// the addresses of an explicit EndpointSlice that names it, else the workloads
// its Selector matches (auto-derived). Addresses are mapped back to matrix
// endpoint IDs via ipToID; addresses with no matching endpoint are dropped
// (they have no row/col to OR against).
func serviceBackendIDs(svc ServiceInput, req Request, ipToID map[string]string) []string {
	var addrs []string
	explicit := false
	for _, s := range req.EndpointSlices {
		if s.ServiceName == svc.Name && s.Namespace == svc.Namespace {
			addrs = append(addrs, s.Addresses...)
			explicit = true
		}
	}
	if !explicit {
		if auto, hits := autoSliceForService(svc, req.Endpoints); hits > 0 {
			addrs = auto.Addresses
		}
	}
	var ids []string
	seen := map[string]bool{}
	for _, a := range addrs {
		if id, ok := ipToID[a]; ok && !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	return ids
}

// actorKind discriminates the two row/col flavors. The matrix loop branches on
// it for hook semantics; the synthetic-WEP helpers don't care (a HEP's tier
// list shape is identical to a WEP's after we swap which list goes into
// Tiers).
type actorKind int

const (
	actorWEP actorKind = iota
	actorHEP
)

// actor is one row/col of the connectivity matrix. For workloads we carry the
// calc-graph-computed *proto.WorkloadEndpoint directly. For HEPs we carry the
// *proto.HostEndpoint and lazily synth a WEP-shaped struct per tier flavor on
// demand (normal / forward / preDNAT / untracked), so checker.Evaluate sees
// the right tier list as its Tiers field.
type actor struct {
	id   string
	kind actorKind
	ip   net.IP
	node string

	wep *proto.WorkloadEndpoint // populated when kind == actorWEP
	hep *proto.HostEndpoint     // populated when kind == actorHEP

	// unpoliced marks a node with no HostEndpoint: its own egress/ingress
	// are unpoliced (Calico doesn't filter host traffic until a HEP exists), so
	// the matrix loop skips evaluating policy on this actor's side of a flow.
	unpoliced bool

	// role echoes Endpoint.Role (workload endpoints only) so actorKindString can
	// distinguish an external destination from an unpoliced host — both are
	// unpoliced WEPs and otherwise identical to the evaluator. Empty for HEPs.
	role string
}

func (a *actor) normalWEP() *proto.WorkloadEndpoint {
	if a.kind == actorWEP {
		return a.wep
	}
	return hepAsWEP(a.hep, a.hep.GetTiers())
}

func (a *actor) forwardWEP() *proto.WorkloadEndpoint {
	return hepAsWEP(a.hep, a.hep.GetForwardTiers())
}

func (a *actor) preDnatWEP() *proto.WorkloadEndpoint {
	return hepAsWEP(a.hep, a.hep.GetPreDnatTiers())
}

func (a *actor) untrackedWEP() *proto.WorkloadEndpoint {
	return hepAsWEP(a.hep, a.hep.GetUntrackedTiers())
}

// hepAsWEP packages a HEP into a WEP shape carrying just the tier list we
// want the checker to walk. ProfileIds copies through so HEPs that match a
// profile (rare; usually empty) follow the same fall-through Calico does.
// Name is filled in so debug logs identify the right endpoint.
// forwardTierHas reports whether any of the HEP's applyOnForward tiers carries a
// policy in the requested direction (ingress=true → ingress policies). Used to
// gate the forward overlay per direction so a single-direction applyOnForward
// policy leaves the unspecified direction's forwarded traffic default-allowed,
// matching Calico (see the overlay call site).
func forwardTierHas(hep *proto.HostEndpoint, ingress bool) bool {
	for _, t := range hep.GetForwardTiers() {
		if ingress && len(t.GetIngressPolicies()) > 0 {
			return true
		}
		if !ingress && len(t.GetEgressPolicies()) > 0 {
			return true
		}
	}
	return false
}

func hepAsWEP(hep *proto.HostEndpoint, tiers []*proto.TierInfo) *proto.WorkloadEndpoint {
	if hep == nil {
		return nil
	}
	return &proto.WorkloadEndpoint{
		Name:       hep.GetName(),
		Tiers:      tiers,
		ProfileIds: hep.GetProfileIds(),
	}
}

// actorBundle is the result of buildActors: the row/col list plus an index of
// HEPs by node (for the applyOnForward / preDNAT overlays that fan out across
// HEPs on the source or destination node) plus any warnings (e.g. HEPs with
// no ExpectedIPs that we couldn't admit to the matrix).
type actorBundle struct {
	list       []*actor
	hepsByNode map[string][]*actor
	warnings   []string
}

// buildActors assembles the row/col list: workload endpoints first (preserving
// their input order, which matters for matrix snapshot stability), then HEPs.
// A HEP with no ExpectedIPs is excluded from the matrix (no IP → can't probe)
// but still indexed in hepsByNode so its applyOnForward / preDNAT tiers can
// gate flows through its node. The matrix-membership rule is intentional: HEP
// hooks fire on whoever traverses the node, regardless of whether the HEP
// itself is reachable.
func buildActors(req Request, wepByID map[string]*proto.WorkloadEndpoint,
	hepByName map[string]*proto.HostEndpoint) actorBundle {
	out := actorBundle{hepsByNode: map[string][]*actor{}}
	for _, ep := range req.Endpoints {
		out.list = append(out.list, &actor{
			id:        ep.ID,
			kind:      actorWEP,
			ip:        net.ParseIP(ep.IP),
			node:      ep.Node,
			wep:       wepByID[ep.ID],
			unpoliced: ep.Unpoliced,
			role:      ep.Role,
		})
	}
	for _, hep := range req.HostEndpoints {
		hp := hepByName[hep.Name]
		if hp == nil {
			// Updateprocessor rejected it or the calc graph hasn't emitted
			// (e.g. malformed ExpectedIPs). feedExtraResources already surfaced
			// the conversion error; no need to re-warn here.
			continue
		}
		// Mirror Calico's dataplane: doNotTrack policy is silently ignored on an
		// all-interfaces (interfaceName: "*") HostEndpoint. The calc graph still
		// splits doNotTrack rules into UntrackedTiers, but felix's endpoint
		// manager refuses to program untracked chains for a "*" HEP — see
		// felix/dataplane/linux/endpoint_mgr.go ("DoNotTrack policy is not
		// supported for a HEP with `interfaceName: *`; ignoring it"). Drop them
		// here so the engine predicts what the dataplane actually enforces (the
		// HEP's normal/preDNAT/applyOnForward tiers are unaffected).
		if hep.InterfaceName == "*" && len(hp.GetUntrackedTiers()) > 0 {
			hp.UntrackedTiers = nil
			out.warnings = append(out.warnings, fmt.Sprintf(
				"HostEndpoint %q: doNotTrack policy is not supported on an all-interfaces "+
					"(interfaceName: \"*\") HostEndpoint and is ignored (matches Calico dataplane behaviour)",
				hep.Name))
		}

		id := "host/" + hep.Name
		var ip net.IP
		if len(hep.ExpectedIPs) > 0 {
			ip = net.ParseIP(hep.ExpectedIPs[0])
		}
		a := &actor{
			id:   id,
			kind: actorHEP,
			ip:   ip,
			node: hep.Node,
			hep:  hp,
		}
		out.hepsByNode[hep.Node] = append(out.hepsByNode[hep.Node], a)
		if ip == nil {
			out.warnings = append(out.warnings,
				fmt.Sprintf("HostEndpoint %q has no ExpectedIPs; excluded from matrix rows/cols "+
					"but its forward/preDNAT tiers still gate flows on node %q", hep.Name, hep.Node))
			continue
		}
		out.list = append(out.list, a)
	}
	return out
}

// applyEndpointIP sets IPv4Nets or IPv6Nets on the WorkloadEndpoint based on
// the parsed IP family of ep.IP. Falls back to IPv4 with a /32 when parsing
// fails so a malformed entry still produces an endpoint shape (the calc graph
// just won't match any IPv4 rule against it).
func applyEndpointIP(wep *model.WorkloadEndpoint, ip string) {
	parsed := libnet.ParseIP(ip)
	if parsed != nil && parsed.To4() == nil {
		wep.IPv6Nets = []libnet.IPNet{libnet.MustParseCIDR(ip + "/128")}
		return
	}
	wep.IPv4Nets = []libnet.IPNet{libnet.MustParseCIDR(ip + "/32")}
}

// applyEndpointPorts copies declared named ports onto the WorkloadEndpoint so
// policies that reference ports by name (e.g. `ports: [http]`) resolve. The
// model uses TCP-like proto names; we accept any case and skip unknown.
func applyEndpointPorts(wep *model.WorkloadEndpoint, ports []EndpointPort) {
	if len(ports) == 0 {
		return
	}
	out := make([]model.EndpointPort, 0, len(ports))
	for _, p := range ports {
		name := strings.ToLower(strings.TrimSpace(p.Protocol))
		if name == "" {
			name = "tcp"
		}
		out = append(out, model.EndpointPort{
			Name:     p.Name,
			Protocol: numorstring.ProtocolFromString(name),
			Port:     uint16(p.Port),
		})
	}
	wep.Ports = out
}
