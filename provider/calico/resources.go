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
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	libnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// feedExtraResources pushes the optional Request resources (host endpoints,
// network sets, services, endpoint slices) into the calc graph via the same
// `send` callback eval.go uses for policies. Returns warnings the caller
// merges into Response.Warnings; hard parse errors become errors.
//
// ServiceAccounts are handled by label-projection in eval.go, not here:
// instead of feeding a ksa.* profile + indirecting through ProfileIDs, we
// stamp pcsa.* labels directly onto each endpoint whose ServiceAccountName
// matches. The end result is identical — the calc graph sees the same labels
// — and we avoid a second updateprocessor wire-up.
func feedExtraResources(send func(model.Key, any), req Request) (warnings, errs []string) {
	for _, hep := range req.HostEndpoints {
		if err := feedHostEndpoint(send, hep); err != nil {
			errs = append(errs, fmt.Sprintf("HostEndpoint %q: %v", hep.Name, err))
		}
	}
	for _, ns := range req.NetworkSets {
		if err := feedNetworkSet(send, ns); err != nil {
			errs = append(errs, fmt.Sprintf("NetworkSet %q/%q: %v", ns.Namespace, ns.Name, err))
		}
	}
	for _, gns := range req.GlobalNetworkSets {
		if err := feedGlobalNetworkSet(send, gns); err != nil {
			errs = append(errs, fmt.Sprintf("GlobalNetworkSet %q: %v", gns.Name, err))
		}
	}
	for _, svc := range req.Services {
		feedService(send, svc)
	}
	for _, slice := range req.EndpointSlices {
		feedEndpointSlice(send, slice, nil)
	}
	// Auto-derive endpoint slices for services that didn't supply one but whose
	// Selector matches workload endpoints — saves dataset authors from typing
	// the slice manually for the common case. The slice carries the Service's
	// ports so Felix's service IPSet (which is keyed on ip+port+proto when
	// IncludePorts is true) picks up the membership.
	for _, svc := range req.Services {
		if hasSliceFor(req.EndpointSlices, svc) {
			continue
		}
		auto, hits := autoSliceForService(svc, req.Endpoints)
		if hits > 0 {
			feedEndpointSlice(send, auto, svc.Ports)
			warnings = append(warnings,
				fmt.Sprintf("auto-derived EndpointSlice for Service %s/%s from %d matching workloads",
					svc.Namespace, svc.Name, hits))
		}
	}
	return warnings, errs
}

func feedHostEndpoint(send func(model.Key, any), hep HostEndpointInput) error {
	// Validate ExpectedIPs early so a malformed entry surfaces a useful error
	// instead of being silently dropped by the updateprocessor.
	for _, s := range hep.ExpectedIPs {
		if ip := libnet.ParseIP(s); ip == nil {
			return fmt.Errorf("bad ExpectedIP %q", s)
		}
	}
	// Force the v3 Spec.Node to the engine's hostname so calc graph's
	// endpointHostnameFilter accepts the HEP as "local". HostEndpointInput.Node
	// stays as the caller supplied it on the Request slice — eval.go's
	// buildActors keys the forward/preDNAT overlay on that value, so multi-node
	// dataset semantics still work even though the calc graph thinks every HEP
	// lives on this one synthetic node.
	v3hep := &apiv3.HostEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: hep.Name, Labels: hep.Labels},
		Spec: apiv3.HostEndpointSpec{
			Node:          hostname,
			InterfaceName: hep.InterfaceName,
			ExpectedIPs:   hep.ExpectedIPs,
		},
	}
	return process(send, updateprocessors.NewHostEndpointUpdateProcessor(),
		model.ResourceKey{Kind: apiv3.KindHostEndpoint, Name: hep.Name}, v3hep)
}

func feedNetworkSet(send func(model.Key, any), ns NetworkSetInput) error {
	v3ns := &apiv3.NetworkSet{
		ObjectMeta: metav1.ObjectMeta{Name: ns.Name, Namespace: ns.Namespace, Labels: ns.Labels},
		Spec:       apiv3.NetworkSetSpec{Nets: ns.Nets},
	}
	return process(send, updateprocessors.NewNetworkSetUpdateProcessor(),
		model.ResourceKey{Kind: apiv3.KindNetworkSet, Name: ns.Name, Namespace: ns.Namespace}, v3ns)
}

func feedGlobalNetworkSet(send func(model.Key, any), gns GlobalNetworkSetInput) error {
	v3 := &apiv3.GlobalNetworkSet{
		ObjectMeta: metav1.ObjectMeta{Name: gns.Name, Labels: gns.Labels},
		Spec:       apiv3.GlobalNetworkSetSpec{Nets: gns.Nets},
	}
	return process(send, updateprocessors.NewGlobalNetworkSetUpdateProcessor(),
		model.ResourceKey{Kind: apiv3.KindGlobalNetworkSet, Name: gns.Name}, v3)
}

// feedService and feedEndpointSlice send the Kubernetes-typed value directly:
// the calc graph's services_addr_indexer / dataplane_passthru consume
// model.ResourceKey{Kind: KindKubernetesService} and KindKubernetesEndpointSlice
// without going through a syncer updateprocessor.
func feedService(send func(model.Key, any), svc ServiceInput) {
	k := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: svc.Namespace},
		Spec: corev1.ServiceSpec{
			Selector: svc.Selector,
			Ports:    toCoreServicePorts(svc.Ports),
		},
	}
	send(model.ResourceKey{Kind: model.KindKubernetesService, Name: svc.Name, Namespace: svc.Namespace}, &k)
}

// feedEndpointSlice emits a discovery/v1 EndpointSlice. svcPorts (optional)
// gets translated to slice-level Ports — required for Felix's service IPSet
// path, which is keyed on (ip, port, proto) when IncludePorts is true and
// skips endpoints whose slice has no Ports declared.
func feedEndpointSlice(send func(model.Key, any), s EndpointSliceInput, svcPorts []ServicePort) {
	addrType := discoveryv1.AddressTypeIPv4
	for _, a := range s.Addresses {
		if strings.Contains(a, ":") {
			addrType = discoveryv1.AddressTypeIPv6
			break
		}
	}
	es := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.Name,
			Namespace: s.Namespace,
			Labels:    map[string]string{discoveryv1.LabelServiceName: s.ServiceName},
		},
		AddressType: addrType,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: s.Addresses,
		}},
		Ports: toSlicePorts(svcPorts),
	}
	send(model.ResourceKey{Kind: model.KindKubernetesEndpointSlice, Name: s.Name, Namespace: s.Namespace}, &es)
}

func toSlicePorts(svcPorts []ServicePort) []discoveryv1.EndpointPort {
	if len(svcPorts) == 0 {
		return nil
	}
	out := make([]discoveryv1.EndpointPort, 0, len(svcPorts))
	for _, p := range svcPorts {
		port := int32(p.Port)
		proto := corev1.ProtocolTCP
		switch strings.ToLower(p.Protocol) {
		case "udp":
			proto = corev1.ProtocolUDP
		case "sctp":
			proto = corev1.ProtocolSCTP
		}
		out = append(out, discoveryv1.EndpointPort{
			Name:     ptrString(p.Name),
			Protocol: &proto,
			Port:     &port,
		})
	}
	return out
}

func ptrString(s string) *string { return &s }

// applyInlineResources normalizes a Request by moving any pasted
// ServiceAccount/Service manifests out of Policies into the typed slices, and
// returns the normalized Request plus parse errors. The public entry points
// (Evaluate, RenderIptables, RenderBPF) call this once up front so every
// downstream consumer sees the same Request — crucially both buildGraph and
// eval.go's matrix service-column builder, which read req.Services
// independently. Doing it per-entry rather than inside buildGraph is what makes
// a pasted Service show up as a matrix column, not just resolve in rules.
func applyInlineResources(req Request) (Request, []string) {
	rem, sas, svcs, errs := extractInlineResources(req.Policies)
	if len(sas)+len(svcs)+len(errs) == 0 {
		return req, nil // nothing inline — leave the Request (and its slices) untouched
	}
	req.Policies = rem
	req.ServiceAccounts = append(req.ServiceAccounts, sas...)
	req.Services = append(req.Services, svcs...)
	return req, errs
}

// extractInlineResources peels ServiceAccount and Service manifests out of the
// policy list and converts them to the typed Request inputs. Unlike the policy
// kinds, these never go through feedPolicy: a ServiceAccount's labels are
// projected onto endpoints via saIndex (which buildGraph populates *before* it
// builds endpoints), and a Service flows through feedExtraResources (which also
// auto-derives its EndpointSlice). Routing them here lets a caller paste them as
// ordinary k8s manifests alongside policies — the editor's paste box and the
// testcase loader both funnel every doc into Policies.
//
// Returns the policies with SA/Service docs removed, the parsed inputs to merge
// into the Request, and parse errors (surfaced in Response.Errors like
// feedPolicy's). A doc whose kind can't even be read is left in place so
// feedPolicy reports the malformed-YAML error in its usual form rather than
// being double-reported here.
func extractInlineResources(policies []PolicyInput) (remaining []PolicyInput, sas []ServiceAccountInput, svcs []ServiceInput, errs []string) {
	for _, p := range policies {
		var tm struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(p.YAML), &tm); err != nil {
			remaining = append(remaining, p)
			continue
		}
		switch tm.Kind {
		case "ServiceAccount":
			var sa corev1.ServiceAccount
			if err := yaml.Unmarshal([]byte(p.YAML), &sa); err != nil {
				errs = append(errs, fmt.Sprintf("parse ServiceAccount: %v", err))
				continue
			}
			sas = append(sas, ServiceAccountInput{
				Name:      sa.Name,
				Namespace: sa.Namespace,
				Labels:    sa.Labels,
			})
		case "Service":
			var svc corev1.Service
			if err := yaml.Unmarshal([]byte(p.YAML), &svc); err != nil {
				errs = append(errs, fmt.Sprintf("parse Service: %v", err))
				continue
			}
			svcs = append(svcs, ServiceInput{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Selector:  svc.Spec.Selector,
				Ports:     fromCoreServicePorts(svc.Spec.Ports),
			})
		default:
			remaining = append(remaining, p)
		}
	}
	return remaining, sas, svcs, errs
}

// fromCoreServicePorts is the inverse of toCoreServicePorts: it maps a parsed
// corev1.Service's ports back into the engine's ServicePort form, carrying only
// the fields the engine consumes. Protocol defaults to tcp (matching both
// Kubernetes' own default and toCoreServicePorts) since a pasted manifest that
// omits protocol hasn't been through the API server's defaulting.
func fromCoreServicePorts(ps []corev1.ServicePort) []ServicePort {
	if len(ps) == 0 {
		return nil
	}
	out := make([]ServicePort, 0, len(ps))
	for _, p := range ps {
		proto := "tcp"
		switch p.Protocol {
		case corev1.ProtocolUDP:
			proto = "udp"
		case corev1.ProtocolSCTP:
			proto = "sctp"
		}
		var target string
		if p.TargetPort.IntValue() != 0 || p.TargetPort.StrVal != "" {
			target = p.TargetPort.String()
		}
		out = append(out, ServicePort{
			Name:       p.Name,
			Port:       int(p.Port),
			Protocol:   proto,
			TargetPort: target,
		})
	}
	return out
}

func toCoreServicePorts(ps []ServicePort) []corev1.ServicePort {
	if len(ps) == 0 {
		return nil
	}
	out := make([]corev1.ServicePort, 0, len(ps))
	for _, p := range ps {
		proto := corev1.ProtocolTCP
		switch strings.ToLower(p.Protocol) {
		case "udp":
			proto = corev1.ProtocolUDP
		case "sctp":
			proto = corev1.ProtocolSCTP
		}
		out = append(out, corev1.ServicePort{
			Name:     p.Name,
			Port:     int32(p.Port),
			Protocol: proto,
		})
	}
	return out
}

func hasSliceFor(slices []EndpointSliceInput, svc ServiceInput) bool {
	for _, s := range slices {
		if s.ServiceName == svc.Name && s.Namespace == svc.Namespace {
			return true
		}
	}
	return false
}

// autoSliceForService synthesises an EndpointSlice whose Addresses are the IPs
// of every workload endpoint matching the Service's Selector (intersected with
// the Service's namespace). Returns the slice and a hit count so the caller
// can decide whether the slice is worth emitting.
func autoSliceForService(svc ServiceInput, endpoints []Endpoint) (EndpointSliceInput, int) {
	var addrs []string
	for _, ep := range endpoints {
		if ep.Namespace != svc.Namespace {
			continue
		}
		if !labelsMatch(ep.Labels, svc.Selector) {
			continue
		}
		if ep.IP != "" {
			addrs = append(addrs, ep.IP)
		}
	}
	return EndpointSliceInput{
		Name:        svc.Name + "-auto",
		Namespace:   svc.Namespace,
		ServiceName: svc.Name,
		Addresses:   addrs,
	}, len(addrs)
}

func labelsMatch(have, want map[string]string) bool {
	if len(want) == 0 {
		return false // a Service with no selector doesn't auto-select workloads
	}
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// projectServiceAccountLabels stamps pcsa.<k>=<v> + projectcalico.org/serviceaccount
// + pcsa.projectcalico.org/name onto labels for the given (namespace, sa) pair,
// looking up the SA's labels in saIndex. This is the workload-side mirror of
// what Calico's calc graph does when a profile (ksa.<ns>.<sa>) projects its
// labels via the endpoint's ProfileIDs — we just do it inline to avoid a
// second updateprocessor wiring. Returns the augmented label map.
func projectServiceAccountLabels(labels map[string]string, namespace, sa string,
	saIndex map[string]map[string]string) {
	if sa == "" {
		return
	}
	labels[apiv3.LabelServiceAccount] = sa
	for k, v := range saIndex[namespace+"/"+sa] {
		labels["pcsa."+k] = v
	}
	labels["pcsa.projectcalico.org/name"] = sa
}
