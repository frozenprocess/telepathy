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
	"github.com/frozenprocess/telepathy/api"
	"github.com/frozenprocess/telepathy/provider"
)

// Register the Calico provider on import.
func init() { provider.Register(New()) }

// Provider is the Calico CNI provider: it drives Calico's own Felix code
// (libcalico-go conversion / updateprocessors, felix/calc CalculationGraph,
// app-policy/checker.Evaluate) to compute connectivity, and Felix's native
// renderers to emit iptables/nftables/bpf/hns dataplane. It implements
// provider.Provider and the optional dataplane-rendering capability.
//
// The package-level functions (Evaluate, RenderIptables, …) remain the library
// API; this type is a thin receiver so the binary can select Calico through the
// provider registry. Evaluate is not goroutine-safe (Felix carries process-wide
// singletons); callers in shared processes must serialise.
type Provider struct{}

// New returns the Calico provider.
func New() Provider { return Provider{} }

func (Provider) Name() string { return "calico" }

func (Provider) Capabilities() []api.Capability { return Capabilities() }

func (Provider) Evaluate(req api.Request) api.Response { return Evaluate(req) }

// RenderIptables / RenderBPF / RenderHNS satisfy the optional dataplane-render
// capability (provider.DataplaneRenderer). They delegate to the package
// functions so the existing library API and CLI behaviour are unchanged.
func (Provider) RenderIptables(req api.Request, opts IptablesOptions) IptablesResponse {
	return RenderIptables(req, opts)
}

func (Provider) RenderBPF(req api.Request, opts BPFOptions) BPFResponse {
	return RenderBPF(req, opts)
}

func (Provider) RenderHNS(req api.Request, opts HNSOptions) HNSResponse {
	return RenderHNS(req, opts)
}

// ResolveTierMatches exposes the Calico-specific tier/policy match trace.
func (Provider) ResolveTierMatches(req api.Request) TierMatchResponse {
	return ResolveTierMatches(req)
}
