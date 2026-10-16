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

// Command telepathy-engine-cilium is the out-of-process Cilium provider. It is
// built as its OWN Go module (engines/cilium) over Cilium's untouched source
// tree (../../third_party/cilium), so it uses Cilium's native dependency
// versions (eBPF, envoy, its own controller-runtime, …) with no reconciliation
// against Calico — which is the whole reason it lives in a separate binary. The
// main `telepathy` shell dispatches `-provider cilium` to it over the
// vendor-neutral JSON contract: an api.Request on stdin, an api.Response on
// stdout.
//
// It drives Cilium's own policy.LookupFlow (pkg/policy/lookup.go) offline:
// fabricate an identity per endpoint (identity.NewIdentity), seed the
// SelectorCache with their labels, load rules via Repository.MustAddList after
// CiliumNetworkPolicy.Parse (or Repository.ReplaceByResource for plain k8s
// NetworkPolicy), then LookupFlow per src->dst pair for the verdict (see
// eval.go). Today it evaluates CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy
// and k8s NetworkPolicy; the policy-program dump (EndpointPolicy.GetMapState())
// is the next step.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/frozenprocess/telepathy/api"
)

func main() {
	caps := flag.Bool("capabilities", false, "print this engine's capabilities as JSON and exit")
	flag.Parse()

	if *caps {
		if err := json.NewEncoder(os.Stdout).Encode(capabilities()); err != nil {
			fail("encode capabilities: %v", err)
		}
		return
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("read request: %v", err)
	}
	req, err := api.DecodeRequest(data)
	if err != nil {
		fail("%v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(evaluate(req)); err != nil {
		fail("encode response: %v", err)
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

// capabilities lists what the Cilium engine honors. Entries with
// Supported=false are recognised but not yet evaluated. This mirrors the
// offline-feasibility scan of Cilium v1.19: everything statically resolvable
// from policy + identities is reachable; FQDN/Services/L7/auth need runtime
// state and stay unsupported. Printed as JSON for the shell's `version` banner
// via the -capabilities flag.
func capabilities() []api.Capability {
	return []api.Capability{
		{Name: "kind: CiliumNetworkPolicy (cilium.io/v2)", Supported: true,
			Notes: "CiliumNetworkPolicy.Parse -> api.Rules -> Repository.MustAddList, evaluated via policy.LookupFlow"},
		{Name: "kind: CiliumClusterwideNetworkPolicy (cilium.io/v2)", Supported: true},
		{Name: "kind: NetworkPolicy (k8s)", Supported: true,
			Notes: "via k8s.ParseNetworkPolicy -> policy.PolicyEntries -> Repository.ReplaceByResource (Cilium's own k8s seam)"},
		{Name: "L3 endpoint/label selectors", Supported: true,
			Notes: "EndpointSelector resolved to identities via the real SelectorCache"},
		{Name: "L3 CIDR (+except, CIDRGroups)", Supported: true,
			Notes: "an off-cluster peer (Role \"external\") gets a world+CIDR identity from its IP, so toCIDR/fromCIDR " +
				"and the world entity match it; in-cluster pods keep their label identity, so a CIDR covering a pod IP does not select the pod"},
		{Name: "entities (world/host/remote-node/kube-apiserver/…)", Supported: true,
			Notes: "reserved-identity selectors resolve; endpoints are labeled workloads, so a world/host peer must be modeled as such"},
		{Name: "L4 ports (numeric, ranges, named)", Supported: true,
			Notes: "named ports resolve against the destination endpoint's declared ports"},
		{Name: "ICMP type/code", Supported: true},
		{Name: "deny policies (Ingress/EgressDeny) + precedence", Supported: true,
			Notes: "Deny wins over Allow within a tier; Pass skips the rest of the tier"},
		{Name: "default-deny / enforcement mode", Supported: true,
			Notes: "an endpoint selected by any policy is default-deny for that direction (Cilium's default mode)"},
		{Name: "toFQDNs (DNS)", Supported: false,
			Notes: "needs a resolver; pre-resolve to CIDRs as a workaround (cf. Calico Request.DNS)"},
		{Name: "toServices", Supported: false, Notes: "needs service->endpoints resolution"},
		{Name: "L7 HTTP / DNS visibility", Supported: false,
			Notes: "Envoy-bound; not offline-evaluable (Calico evaluates L7 HTTP via Dikastes — a genuine gap)"},
		{Name: "authentication (mTLS/SPIFFE), Groups (AWS)", Supported: false,
			Notes: "runtime-only"},
		{Name: "policy-program dump (BPF policy MapState)", Supported: false,
			Notes: "offline analog of Calico's BPF render: EndpointPolicy.GetMapState() in userspace, no kernel — next step"},
	}
}
