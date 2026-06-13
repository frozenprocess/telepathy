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

// Command telepathy-engine-antrea is the out-of-process Antrea provider. It is
// built as its OWN Go module (engines/antrea) over Antrea's untouched source
// tree, so it uses Antrea's native dependency versions (network-policy-api,
// controller-runtime, …) with no reconciliation against Calico — which is the
// whole reason it lives in a separate binary. The main `telepathy` shell
// dispatches `-provider antrea` to it over the vendor-neutral JSON contract:
// an api.Request on stdin, an api.Response on stdout.
//
// It drives Antrea's own grouping.GroupEntityIndex offline to resolve
// pod/namespace selectors, then applies Kubernetes NetworkPolicy semantics over
// the resolved members (see eval.go / harness.go).
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

// capabilities lists what the Antrea engine honors today. Entries with
// Supported=false are recognised but not yet evaluated. Printed as JSON for the
// shell's `version` banner via the -capabilities flag.
func capabilities() []api.Capability {
	return []api.Capability{
		{Name: "kind: NetworkPolicy (k8s)", Supported: true,
			Notes: "driven through Antrea's real grouping.GroupEntityIndex selector engine"},
		{Name: "spec.podSelector", Supported: true},
		{Name: "ingress / egress rules", Supported: true,
			Notes: "two-sided: a flow must clear dst ingress and src egress"},
		{Name: "from/to.podSelector + namespaceSelector", Supported: true},
		{Name: "from/to.ipBlock (cidr + except)", Supported: true},
		{Name: "ports (numeric, named, ranges)", Supported: true,
			Notes: "named ports resolve against the destination endpoint's declared ports"},
		{Name: "policyTypes (Ingress/Egress isolation)", Supported: true},
		{Name: "kind: ClusterNetworkPolicy / NetworkPolicy (crd.antrea.io)", Supported: false,
			Notes: "Antrea tiers/priorities/actions — next step now that the full controller compiles in this module"},
		{Name: "kind: Tier", Supported: false},
		{Name: "kind: (Admin|Baseline)NetworkPolicy", Supported: false},
		{Name: "dataplane render (openflow)", Supported: false},
	}
}
