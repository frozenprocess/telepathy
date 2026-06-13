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

// Package api is the vendor-neutral contract shared by every CNI provider. It
// defines the wire schema — Request (topology + policies + probe) and Response
// (the connectivity matrix) — plus the provider-agnostic operations that work
// purely on that schema: decoding (DecodeRequest/DecodeResponse/
// ParsePolicyManifests), connectivity diffing (DiffResponses), and assertion
// checking (RunAssertions). It imports no CNI-specific code; a provider (e.g.
// provider/calico) imports this package, not the other way round.
//
// The actual policy evaluation lives behind the provider.Provider interface;
// RunAssertions takes the chosen provider's Evaluate as a function argument so
// this package stays free of any provider dependency. Evaluation itself is not
// guaranteed goroutine-safe (Calico's Felix calc graph carries process-wide
// singletons), so callers in shared-process environments must serialise calls.
package api

// Capability describes one policy feature or resource kind a provider honors.
// A provider returns its set from Provider.Capabilities; callers (and lint) use
// it to discover the feature surface before trusting a verdict. The shape is
// neutral; the entries are provider-specific.
type Capability struct {
	Name      string `json:"name"`
	Supported bool   `json:"supported"`
	Notes     string `json:"notes,omitempty"`
}

// EndpointPort declares a named port on an endpoint, so policies that
// reference ports by name (e.g. `ports: [http]`) resolve to a concrete
// (protocol, port) tuple at evaluation time. Protocol is one of
// tcp / udp / sctp (case-insensitive); empty defaults to tcp.
type EndpointPort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

// Endpoint is one workload pod in the evaluated topology. ID is the harness's
// "<namespace>/<app>" form and is what shows up as both row and column keys
// in Response.Matrix. IP may be IPv4 or IPv6; the engine picks IPv4Nets vs
// IPv6Nets per endpoint based on the parsed family.
//
// Node is optional and only matters for HEP overlays: a HostEndpointInput
// with the same Node value applies its applyOnForward / preDNAT / doNotTrack
// hooks to flows that originate or terminate on this workload. Default "" is
// the right value for single-node datasets — leave it empty everywhere and
// every HEP applies to every flow.
type Endpoint struct {
	ID                 string            `json:"id"`
	Namespace          string            `json:"namespace"`
	Name               string            `json:"name"`
	IP                 string            `json:"ip"`
	Labels             map[string]string `json:"labels"`
	Ports              []EndpointPort    `json:"ports,omitempty"`
	ServiceAccountName string            `json:"serviceAccountName,omitempty"`
	Node               string            `json:"node,omitempty"`

	// Unpoliced marks a node that has no HostEndpoint. Calico does not
	// police host traffic until a HEP exists, so the evaluator treats this
	// endpoint's own egress/ingress as unconditionally allowed — only the peer's
	// policy limits a flow. Lets the harness surface an unprotected node's true
	// posture (e.g. it can still reach the internet under a pod-only deny-all).
	Unpoliced bool `json:"unpoliced,omitempty"`

	// Role is the caller's semantic intent for this endpoint, surfaced verbatim
	// as the matching Actor.Kind in Response.Actors so every consumer types a
	// row/col the same way. The evaluator does NOT branch on it (Unpoliced still
	// governs the policy semantics) — it exists because an external destination
	// and an unpoliced host are both Unpoliced WEPs and otherwise indistinguishable.
	//   ""/"workload" → a cluster pod
	//   "external"    → an off-cluster destination ("the internet", a partner API)
	//   "host"        → an unpoliced host (a node with no HostEndpoint)
	// HostEndpoints (Request.HostEndpoints) always report Kind "hep" regardless.
	Role string `json:"role,omitempty"`
}

// NamespaceInput supplies the labels a real Namespace object would have. The
// engine projects these onto each endpoint as pcns.<k>=<v>, which is the
// label form Calico's calc graph compiles namespaceSelector rules against.
type NamespaceInput struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

// ServiceAccountInput supplies the labels a real ServiceAccount object would
// have. The calc graph projects these onto endpoints whose ServiceAccountName
// matches as pcsa.<k>=<v> labels, which is the form Calico uses to compile
// rule-level `source/destination.serviceAccounts.selector` matching.
type ServiceAccountInput struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// HostEndpointInput models a Calico HostEndpoint (a node interface or whole
// node treated as a policy-bearing endpoint). HEPs are full rows/cols in the
// connectivity matrix: their ID is "host/<Name>" and ExpectedIPs[0] supplies
// the source/dest IP for probes.
//
// Calico compiles HEP policies into four separate tier lists per HEP — normal
// (terminating traffic), ForwardTiers (applyOnForward — transit traffic),
// PreDnatTiers (preDNAT — pre-kube-proxy ingress hook), UntrackedTiers
// (doNotTrack — pre-conntrack, requires both directions). The matrix loop
// applies each overlay where it makes semantic sense (see eval.go). Node ties
// HEPs to workloads on the same node for the forward/preDNAT overlays.
type HostEndpointInput struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Node          string            `json:"node,omitempty"`
	InterfaceName string            `json:"interfaceName,omitempty"`
	ExpectedIPs   []string          `json:"expectedIPs"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// NetworkSetInput models a namespaced Calico NetworkSet (a bag of CIDRs +
// labels that policy rules can match by selector). GlobalNetworkSetInput is
// the cluster-scoped variant.
type NetworkSetInput struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Nets      []string          `json:"nets,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type GlobalNetworkSetInput struct {
	Name   string            `json:"name"`
	Nets   []string          `json:"nets,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// ServiceInput / EndpointSliceInput supply enough of a Kubernetes Service +
// its endpoint set to resolve `source/destination.services` references in
// Calico rules. The calc graph turns the matched endpoint IPs into a per-rule
// IP set; the harness can either supply EndpointSlices explicitly or let the
// engine auto-derive them from workload endpoints that match `Selector`.
type ServiceInput struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Selector  map[string]string `json:"selector,omitempty"`
	Ports     []ServicePort     `json:"ports,omitempty"`

	// Type is the Kubernetes Service type: "" / "ClusterIP" (default) or
	// "NodePort". The engine treats every Service as ClusterIP semantics
	// (a svc/<ns>/<name> column reachable iff a backend pod is) and ignores
	// Type — it does not model NodePort DNAT. Type exists for the e2e harness,
	// which realizes a NodePort Service so an off-cluster observer can reach a
	// backend via node-IP:nodePort (the only externally routable path, used by
	// preDNAT/NodePort test cases).
	Type string `json:"type,omitempty"`
}

type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol,omitempty"`
	TargetPort string `json:"targetPort,omitempty"`

	// NodePort is the externally reachable port on every node, used only when
	// the Service Type is NodePort. 0 lets Kubernetes auto-assign (the harness
	// reads the assigned value back). Like Type, the engine ignores this.
	NodePort int `json:"nodePort,omitempty"`
}

type EndpointSliceInput struct {
	Name        string   `json:"name"`
	Namespace   string   `json:"namespace"`
	ServiceName string   `json:"serviceName"`
	Addresses   []string `json:"addresses"`
}

// PolicyInput is a single policy manifest. Flavor disambiguates the two
// "kind: NetworkPolicy" cases: "k8s" for networking.k8s.io/v1 NetworkPolicy
// (converted via libcalico-go's conversion.Converter), "calico" for the
// projectcalico.org/v3 form. Other kinds (GlobalNetworkPolicy, Tier,
// ClusterNetworkPolicy, NetworkSet, …) don't need Flavor — the YAML's
// `kind:` is enough.
type PolicyInput struct {
	Flavor string `json:"flavor"`
	YAML   string `json:"yaml"`
}

// Request is one evaluation: build a calc graph from (Endpoints, Namespaces,
// Policies, …), then probe every ordered pair at (Protocol, Port).
//
// Schema is additive: every field beyond Endpoints / Namespaces / Policies /
// Port / Protocol is optional, so a pre-existing caller that fills only those
// behaves unchanged. New callers can layer features in as needed.
type Request struct {
	Endpoints  []Endpoint       `json:"endpoints"`
	Namespaces []NamespaceInput `json:"namespaces"`
	Policies   []PolicyInput    `json:"policies"`
	Port       int              `json:"port"`
	Protocol   string           `json:"protocol"`

	// Optional probe knobs. Defaults preserve pre-extension behaviour:
	//   SrcPort 12345, HTTP fields nil, ICMP type/code nil.
	SrcPort    int    `json:"srcPort,omitempty"`
	HTTPMethod string `json:"httpMethod,omitempty"`
	HTTPPath   string `json:"httpPath,omitempty"`
	ICMPType   *int   `json:"icmpType,omitempty"`
	ICMPCode   *int   `json:"icmpCode,omitempty"`

	// Optional topology and resource extensions. Each is forwarded to the
	// calc graph through libcalico-go updateprocessors so rules that
	// reference them resolve to real IP sets / label projections.
	ServiceAccounts   []ServiceAccountInput   `json:"serviceAccounts,omitempty"`
	HostEndpoints     []HostEndpointInput     `json:"hostEndpoints,omitempty"`
	NetworkSets       []NetworkSetInput       `json:"networkSets,omitempty"`
	GlobalNetworkSets []GlobalNetworkSetInput `json:"globalNetworkSets,omitempty"`
	Services          []ServiceInput          `json:"services,omitempty"`
	EndpointSlices    []EndpointSliceInput    `json:"endpointSlices,omitempty"`

	// DNS is a stub resolver for `destination.domains` rules: the engine
	// turns each matched domain into the corresponding nets at compile time.
	// When DNS is nil and a policy uses `domains:`, lint flags it.
	DNS map[string][]string `json:"dns,omitempty"`

	// EvaluateStaged opts in to evaluating Staged{Global}NetworkPolicy as
	// if it were enforced. Default: staged policies are silently skipped,
	// matching Calico's runtime behaviour.
	EvaluateStaged bool `json:"evaluateStaged,omitempty"`

	// StrictLint, when true, turns lint warnings (e.g. a policy referencing
	// a feature this engine doesn't honour) into hard errors. Default:
	// warnings surface in Response.Warnings, evaluation still runs.
	StrictLint bool `json:"strictLint,omitempty"`
}

// Response is the connectivity matrix. Keys are "src.ID->dst.ID"; values are
// "allow" iff source egress AND destination ingress both allow the flow.
// Errors collects per-policy parse/conversion failures so the caller can
// surface them without losing the rest of the matrix. Warnings collects
// lint findings (unsupported features etc.) that didn't stop evaluation.
type Response struct {
	Matrix   map[string]string `json:"matrix"`
	Errors   []string          `json:"errors,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
	// Actors is the typed row/col directory for Matrix: one entry per matrix
	// endpoint, in the same order the rows/cols appear. It's the single source
	// of endpoint typing — consumers read Kind here instead of re-deriving
	// [EXT]/[HEP]/[HOST] from id conventions. Probe-independent except Internet.
	Actors []Actor `json:"actors,omitempty"`
}

// Actor is the typed description of one Matrix row/col. Kind is derived from
// the input (Endpoint.Role for workload endpoints, always "hep" for a
// HostEndpoint):
//
//	"workload"       — a cluster pod
//	"external"       — an off-cluster destination (the internet, a partner API)
//	"hep"            — a Calico HostEndpoint (policed node interface)
//	"host-unpoliced" — a node with no HostEndpoint (Unpoliced; host-default-allow)
//
// Internet is this actor's egress posture toward the external actors for the
// evaluated probe: "allow" if it reaches any external, "deny" if none, "" when
// there are no external actors (n/a) or the actor is itself external. Callers
// evaluating multiple probes (e.g. the editor) recompute Internet across their
// visible-probe set; the value here reflects this single Evaluate call.
type Actor struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Node     string `json:"node,omitempty"`
	Internet string `json:"internet,omitempty"`
}
