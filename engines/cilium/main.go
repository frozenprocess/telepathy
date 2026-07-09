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
// Unlike Calico's ordered per-endpoint rule chains, Cilium collapses a
// workload's labels into a numeric security identity and renders policy as a
// {direction, identity, port, protocol} -> verdict table. This engine drives
// Cilium's own pkg/policy offline: it builds a Repository from the request's
// policies, distills each endpoint's SelectorPolicy, and resolves every probe
// via EndpointPolicy.Lookup (see eval.go / harness.go).
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

// capabilities lists what the Cilium engine honors today. Entries with
// Supported=false are recognised but not yet evaluated. Printed as JSON for the
// shell's `version` banner via the -capabilities flag.
//
// k8s NetworkPolicy is driven through Cilium's real pkg/policy; the CRD kinds
// and world/CIDR peers are recognised but not yet evaluated (flip each as its
// path lands in eval.go/harness.go).
func capabilities() []api.Capability {
	return []api.Capability{
		{Name: "kind: NetworkPolicy (k8s)", Supported: true,
			Notes: "parsed via Cilium's pkg/k8s.ParseNetworkPolicy, resolved through pkg/policy.LookupFlow"},
		{Name: "spec.podSelector", Supported: true},
		{Name: "ingress / egress rules", Supported: true,
			Notes: "two-sided: a flow is allowed only if neither src egress nor dst ingress denies it"},
		{Name: "from/to.podSelector + namespaceSelector", Supported: true},
		{Name: "ports (numeric, named, ranges)", Supported: true,
			Notes: "resolved by Cilium; named ports keyed off the destination endpoint"},
		{Name: "policyTypes (Ingress/Egress isolation)", Supported: true},
		{Name: "from/to.ipBlock (cidr + except)", Supported: false,
			Notes: "needs world/CIDR identities for the peer; non-namespaced endpoints not modelled yet"},
		{Name: "kind: CiliumNetworkPolicy (cilium.io)", Supported: false,
			Notes: "label-based identities, L7 (HTTP), entities (world/cluster/host) — after k8s NP"},
		{Name: "kind: CiliumClusterwideNetworkPolicy (cilium.io)", Supported: false},
		{Name: "dataplane render (eBPF policy map)", Supported: false,
			Notes: "Cilium's verdict is a map lookup, not a rule chain; render would dump MapState entries"},
	}
}
