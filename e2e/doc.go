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

//go:build e2e

// Package e2e runs each e2e/testdata/<case>/ on a real kind+Calico cluster and
// compares the dataplane's allow/deny verdict against the in-process engine's
// prediction. It is the ground-truth counterpart to `make verify-all`, which
// only checks the engine against hand-authored `expect` values.
//
// The package is guarded by the `e2e` build tag so it never compiles into the
// normal `go test ./...` run (it requires a live cluster, kubectl, and kind).
// Run it via `make e2e` (which brings the cluster up first) or directly:
//
//	go test -tags e2e -timeout 60m ./e2e/... -v
//	go test -tags e2e ./e2e/... -run 'TestE2E/np-deny-all-ingress' -v
//
// How a case runs (see e2e_test.go for the orchestration):
//
//  1. Parse topology.yaml / assertions.yaml / policy.yaml with the api package
//     (the same types the engine uses — no duplicate schema here).
//  2. Realize the topology as real objects: Namespaces, ServiceAccounts, Pods
//     (each running agnhost as a TCP/UDP/SCTP server plus a netshoot sidecar
//     for ICMP), Services, Calico (Global)NetworkSets and HostEndpoints
//     (realize.go).
//  3. Wait for pods Ready, harvest their real IPs, and build a fictional->real
//     IP map. Rewrite the topology, netsets, HEP IPs and any policy CIDR that
//     contains a fictional endpoint IP so that BOTH the engine and the cluster
//     evaluate identical real-IP inputs (ipmap.go).
//  4. Apply the (rewritten) policy, run the engine over the (rewritten)
//     topology via `telepathy test -json`, and probe every assertion's flow on
//     the cluster with agnhost connect / ping (probe.go).
//  5. Compare engine-vs-cluster per assertion; the test fails on any
//     disagreement. `cluster != expect` rows are reported but not fatal — they
//     flag a questionable assertion rather than an engine bug (report.go).
package e2e
