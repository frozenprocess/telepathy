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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/frozenprocess/telepathy/api"
	"github.com/frozenprocess/telepathy/provider"
	"github.com/frozenprocess/telepathy/provider/calico"
)

// TestEngineAgreesWithCalico is the end-to-end cross-check across the process
// boundary: it runs the in-process Calico provider and the out-of-process
// Antrea engine (via the registered proxy) on the same Kubernetes NetworkPolicy
// input and asserts they produce the same connectivity matrix. Skipped when the
// engine binary hasn't been built (`make build`).
func TestEngineAgreesWithCalico(t *testing.T) {
	engine, err := filepath.Abs("bin/telepathy-engine-antrea")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(engine); err != nil {
		t.Skip("antrea engine binary not built; run `make build`")
	}
	t.Setenv("TELEPATHY_ANTREA_ENGINE", engine)

	topology, err := os.ReadFile("e2e/testdata/sample-topology.yaml")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile("e2e/testdata/sample-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	req, err := api.DecodeRequest(topology)
	if err != nil {
		t.Fatal(err)
	}
	req.Policies = append(req.Policies, api.ParsePolicyManifests(policy)...)

	antreaProvider, ok := provider.Get("antrea")
	if !ok {
		t.Fatal("antrea provider not registered")
	}

	ca := calico.New().Evaluate(req)
	an := antreaProvider.Evaluate(req)
	if len(an.Errors) > 0 {
		t.Fatalf("antrea engine errors: %v", an.Errors)
	}

	keys := map[string]bool{}
	for k := range ca.Matrix {
		keys[k] = true
	}
	for k := range an.Matrix {
		keys[k] = true
	}
	if len(keys) == 0 {
		t.Fatal("empty matrix from both providers")
	}
	for k := range keys {
		if ca.Matrix[k] != an.Matrix[k] {
			t.Errorf("flow %s: calico=%q antrea=%q", k, ca.Matrix[k], an.Matrix[k])
		}
	}
}
