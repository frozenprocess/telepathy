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

import "github.com/frozenprocess/telepathy/api"

// These aliases re-export the vendor-neutral schema (defined in package api)
// under the names this provider's code uses internally. The source of truth is
// package api — these are zero-cost type identities, not new types, so an
// api.Request and a calico.Request are interchangeable. They exist so the bulk
// of the Calico evaluation code (graph/feed/eval/render) reads unqualified
// (Request, Endpoint, …) while the neutral contract lives outside this package.
type (
	Request               = api.Request
	Response              = api.Response
	Endpoint              = api.Endpoint
	EndpointPort          = api.EndpointPort
	NamespaceInput        = api.NamespaceInput
	ServiceAccountInput   = api.ServiceAccountInput
	HostEndpointInput     = api.HostEndpointInput
	NetworkSetInput       = api.NetworkSetInput
	GlobalNetworkSetInput = api.GlobalNetworkSetInput
	ServiceInput          = api.ServiceInput
	ServicePort           = api.ServicePort
	EndpointSliceInput    = api.EndpointSliceInput
	PolicyInput           = api.PolicyInput
	Actor                 = api.Actor
	Capability            = api.Capability

	Assertion       = api.Assertion
	AssertionFile   = api.AssertionFile
	AssertionResult = api.AssertionResult
	AssertionReport = api.AssertionReport
)
