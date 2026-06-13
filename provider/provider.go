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

// Package provider defines the pluggable-CNI seam: the Provider interface every
// CNI engine implements, plus a name-keyed registry the CLI selects from. The
// only universal operation is Evaluate (the connectivity matrix); CNI-specific
// capabilities such as dataplane rendering are optional interfaces a provider
// may additionally implement (see DataplaneRenderer), discovered by type
// assertion.
//
// Providers self-register from an init() (import for side effect), so the CLI
// learns the available set without a compile-time switch.
package provider

import (
	"sort"
	"sync"

	"github.com/frozenprocess/telepathy/api"
)

// Provider is one CNI's policy engine, driven offline. Evaluate is the
// vendor-neutral contract: a Request (topology + policies + probe) in, a
// connectivity-matrix Response out.
type Provider interface {
	// Name is the stable selector ("calico", "antrea").
	Name() string
	// Capabilities lists the policy features and resource kinds this provider
	// honors, surfaced by `version` and usable as a pre-flight lint.
	Capabilities() []api.Capability
	// Evaluate computes the pod-to-pod connectivity matrix for req.
	Evaluate(req api.Request) api.Response
}

// Dataplane rendering is an optional, provider-specific capability. Its
// option/response types are CNI-specific (Calico: iptables/nftables/bpf/hns;
// Antrea: openflow) and live with each provider, so a generic interface here
// would create an import cycle (provider -> calico -> provider). Instead the
// CLI declares the render interface it needs and type-asserts the selected
// provider against it, reporting cleanly when unsupported. Phase 1 keeps
// Calico's existing typed render methods unchanged so `-json` output is
// identical.

var (
	mu       sync.RWMutex
	registry = map[string]Provider{}
)

// Register adds p to the registry under p.Name(). Intended to be called from a
// provider package's init(). A duplicate name overwrites — the last registered
// wins, which keeps test doubles simple.
func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	registry[p.Name()] = p
}

// Get returns the registered provider for name and whether it was found.
func Get(name string) (Provider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	return p, ok
}

// List returns the registered provider names, sorted.
func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
