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

	"sigs.k8s.io/yaml"
)

// Capabilities returns the static set of features this engine honors. Callers
// (notably the policy_llm harness) can use this to lint policies before
// trusting the engine's verdict. Keep in sync with implementation in eval.go,
// feed.go, resources.go, flow.go.
func Capabilities() []Capability {
	return []Capability{
		// Top-level spec
		{Name: "spec.tier", Supported: true},
		{Name: "spec.order", Supported: true},
		{Name: "spec.selector", Supported: true},
		{Name: "spec.namespaceSelector", Supported: true, Notes: "including global()"},
		{Name: "spec.serviceAccountSelector", Supported: true,
			Notes: "label-based; project SA labels via Request.ServiceAccounts"},
		{Name: "spec.types", Supported: true},
		{Name: "spec.doNotTrack", Supported: true,
			Notes: "applies when the HEP is itself src or dst; reply leg is evaluated " +
				"symmetrically so a one-direction-only allow correctly denies the connection"},
		{Name: "spec.preDNAT", Supported: true,
			Notes: "evaluated as an ingress hook on the destination node's HEPs; the probe " +
				"targets the resolved pod IP. Service destinations get a svc/<ns>/<name> " +
				"column (reachable iff a backend pod is — Request.Services), but a preDNAT " +
				"rule matching a ClusterIP literal before DNAT still won't match; select the " +
				"Service (destination.services) or its backend pods instead"},
		{Name: "spec.applyOnForward", Supported: true,
			Notes: "HEPs whose Node matches src.Node or dst.Node gate the flow via their " +
				"ForwardTiers; HEP-as-endpoint flows use Tiers (terminating-traffic) instead"},
		{Name: "spec.performanceHints", Supported: true, Notes: "accepted; no effect on evaluator"},

		// Rule selectors
		{Name: "rule.action (Allow/Deny/Log/Pass)", Supported: true},
		{Name: "rule.protocol / notProtocol",
			Supported: true, Notes: "tcp/udp/icmp/icmpv6/sctp/udplite + numeric 1-255"},
		{Name: "rule.icmp.type / .code", Supported: true,
			Notes: "filtered at feed time (the upstream app-policy/checker we reuse " +
				"matches only by protocol number, so we drop contradictory rules " +
				"before they enter the calc graph). Set Request.ICMPType / .ICMPCode " +
				"to activate; leaving them nil preserves the previous 'ignore' behaviour."},
		{Name: "rule.http (methods, paths)", Supported: true,
			Notes: "set Request.HTTPMethod / HTTPPath; ingress only — egress HTTP is invalid in Calico"},
		{Name: "source/destination.selector + notSelector", Supported: true},
		{Name: "source/destination.namespaceSelector", Supported: true},
		{Name: "source/destination.nets / notNets", Supported: true},
		{Name: "source/destination.ports / notPorts", Supported: true,
			Notes: "numeric and ranges are fully supported. Named ports are accepted on " +
				"endpoints and projected into the calc graph, but the app-policy/checker's " +
				"matchPort path looks up named-port IPSets via port-only strings while Felix " +
				"populates them with 'ip,proto:port' tuples — so rules that reference a named " +
				"port deny by default. Use numeric ports in policies for now."},
		{Name: "source/destination.serviceAccounts.names / selector", Supported: true,
			Notes: "requires Endpoint.ServiceAccountName + matching Request.ServiceAccounts entry"},
		{Name: "source/destination.services", Supported: true,
			Notes: "supply Request.Services (+ optional EndpointSlices, else auto-derived " +
				"from the Selector) to resolve; each Service also gets a dst-only " +
				"svc/<ns>/<name> matrix column, reachable iff a backend pod is"},
		{Name: "destination.domains (FQDN)", Supported: false,
			Notes: "no DNS plumbing yet; provide Request.DNS to pre-resolve as a workaround"},

		// Resources
		{Name: "kind: NetworkPolicy (k8s)", Supported: true},
		{Name: "kind: NetworkPolicy (projectcalico.org/v3)", Supported: true},
		{Name: "kind: GlobalNetworkPolicy", Supported: true},
		{Name: "kind: Tier", Supported: true},
		{Name: "kind: NetworkSet / GlobalNetworkSet", Supported: true},
		{Name: "kind: HostEndpoint", Supported: true,
			Notes: "row/col in the matrix as \"host/<Name>\"; ExpectedIPs[0] supplies the " +
				"probe IP. HEPs without ExpectedIPs still gate forward/preDNAT flows on " +
				"their Node but don't appear as endpoints themselves"},
		{Name: "kind: ClusterNetworkPolicy (policy.networking.k8s.io/v1alpha2)", Supported: true},
		{Name: "kind: (Admin|Baseline)NetworkPolicy (v1alpha1)", Supported: false,
			Notes: "Calico v3.32 ships no v1alpha1 converter; rewrite as v1alpha2 ClusterNetworkPolicy"},
		{Name: "kind: Staged(Global)NetworkPolicy", Supported: true,
			Notes: "by default treated as inactive; set Request.EvaluateStaged=true to enforce"},

		// Probe
		{Name: "probe protocol", Supported: true,
			Notes: "tcp/udp/icmp/icmpv6/sctp/udplite + numeric; L4 port only meaningful for tcp/udp/sctp/udplite"},
		{Name: "probe srcPort / dstPort", Supported: true},
		{Name: "probe httpMethod / httpPath", Supported: true},
		{Name: "probe icmpType / icmpCode", Supported: true,
			Notes: "see rule.icmp.type/.code; nil means 'don't filter on ICMP type/code'."},
		{Name: "IPv4 endpoints", Supported: true},
		{Name: "IPv6 endpoints", Supported: true,
			Notes: "auto-detected per Endpoint.IP family; use ipVersion: 6 in rules to target v6 only"},
	}
}

// lintPolicies inspects each PolicyInput's YAML for features the engine does
// not honor. Returns (warnings, errors). Errors are returned (rather than
// just warned) for cases where evaluation would be silently misleading
// regardless of inputs — currently none; everything is a warning so callers
// retain visibility.
func lintPolicies(req Request) (warnings, errs []string) {
	for _, p := range req.Policies {
		var head struct {
			Kind       string `json:"kind"`
			APIVersion string `json:"apiVersion"`
		}
		if err := yaml.Unmarshal([]byte(p.YAML), &head); err != nil {
			continue
		}
		name := policyDisplayName(p.YAML, head.Kind)

		// v1alpha1 AdminNetworkPolicy / BaselineAdminNetworkPolicy: no
		// converter is available; the policy will fall through feedPolicy's
		// default and surface as an error. We surface a friendlier hint here.
		if strings.HasPrefix(head.APIVersion, "policy.networking.k8s.io/v1alpha1") {
			warnings = append(warnings,
				fmt.Sprintf("%s: v1alpha1 ANP/BANP is not supported by this engine; "+
					"rewrite as policy.networking.k8s.io/v1alpha2 ClusterNetworkPolicy", name))
			continue
		}

		// FQDN / domains: detectable only by reading the rules. Surface a
		// warning when a domains: list appears and Request.DNS has no entries.
		if strings.Contains(p.YAML, "domains:") && len(req.DNS) == 0 {
			warnings = append(warnings,
				fmt.Sprintf("%s: references domains: but Request.DNS is empty — "+
					"FQDN matching will resolve to empty IP sets", name))
		}

		// ICMP type/code: now filtered at feed time when the caller sets
		// Request.ICMPType / .ICMPCode (see icmp.go). When neither is set,
		// the matchers still resolve as wildcards because we have nothing to
		// compare against — surface that so a caller relying on the matcher
		// for verdict differentiation knows to populate the probe fields.
		if hasICMPTypeOrCode(p.YAML) && req.ICMPType == nil && req.ICMPCode == nil {
			warnings = append(warnings,
				fmt.Sprintf("%s: uses icmp.type / icmp.code but Request.ICMPType/ICMPCode "+
					"are unset, so the matcher acts as a wildcard. Set them on the Request "+
					"to filter rules by ICMP type/code.", name))
		}

		// HTTP on egress: structurally invalid in Calico; flag here so the
		// dataset doesn't accumulate examples that would never enforce.
		if hasHTTPOnEgress(p.YAML) {
			warnings = append(warnings,
				fmt.Sprintf("%s: applies http: matchers under egress, which Calico rejects "+
					"(HTTP matchers are ingress-only)", name))
		}

		// doNotTrack / preDNAT / applyOnForward are now enforced through the
		// HEP overlays in eval.go's matrix loop, so we no longer warn here.
		// The Capabilities() entries spell out the residual caveats (preDNAT
		// can't see Service ClusterIPs without a Service-IP probe mode, etc.).

		// Named-port references: see Capabilities() — accepted but the
		// checker can't match them, so they currently deny by default.
		if hasNamedPortRef(p.YAML) {
			warnings = append(warnings,
				fmt.Sprintf("%s: references a named port; the app-policy/checker named-port "+
					"match is incompatible with Felix's IPSet encoding — rules using named "+
					"ports will deny. Rewrite with numeric ports.", name))
		}
	}
	return
}

func policyDisplayName(y, kind string) string {
	for _, line := range strings.Split(y, "\n") {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "name:") {
			return kind + " " + strings.TrimSpace(strings.TrimPrefix(s, "name:"))
		}
	}
	return kind
}

// hasICMPTypeOrCode is a cheap textual check — good enough for lint surface
// since we just want to flag the YAML; a false positive on a string value
// containing the substring is acceptable noise compared to missing the case.
func hasICMPTypeOrCode(y string) bool {
	lines := strings.Split(y, "\n")
	inICMP := false
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "icmp:") || strings.HasPrefix(s, "notICMP:") {
			inICMP = true
			continue
		}
		if inICMP {
			if strings.HasPrefix(s, "type:") || strings.HasPrefix(s, "code:") {
				return true
			}
			if s != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				inICMP = false
			}
		}
	}
	return false
}

// hasHTTPOnEgress flags policies that put http: under egress: (Calico
// validates this away in admission). Detection is structural — we look for
// `egress:` and `http:` co-occurring under a rule, conservatively.
func hasHTTPOnEgress(y string) bool {
	lines := strings.Split(y, "\n")
	section := "" // "ingress" / "egress" / ""
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		switch {
		case strings.HasPrefix(trimmed, "ingress:"):
			section = "ingress"
		case strings.HasPrefix(trimmed, "egress:"):
			section = "egress"
		case strings.HasPrefix(trimmed, "http:") && section == "egress":
			return true
		}
	}
	return false
}

// hasNamedPortRef scans for a `ports:` list inside source/destination whose
// entries are non-numeric — i.e. the policy references a port by name.
// Conservative: any `ports: [...]` entry that isn't an integer or a numeric
// range counts as named.
func hasNamedPortRef(y string) bool {
	for _, line := range strings.Split(y, "\n") {
		s := strings.TrimSpace(line)
		if !strings.HasPrefix(s, "ports:") && !strings.HasPrefix(s, "notPorts:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(s, strings.SplitN(s, ":", 2)[0]+":"))
		// Strip [ and ] and split on commas
		rest = strings.TrimPrefix(rest, "[")
		rest = strings.TrimSuffix(rest, "]")
		for _, tok := range strings.Split(rest, ",") {
			tok = strings.Trim(tok, " '\"")
			if tok == "" {
				continue
			}
			// numeric or range like "80:90"
			isNumericish := true
			for _, c := range tok {
				if (c < '0' || c > '9') && c != ':' {
					isNumericish = false
					break
				}
			}
			if !isNumericish {
				return true
			}
		}
	}
	return false
}
