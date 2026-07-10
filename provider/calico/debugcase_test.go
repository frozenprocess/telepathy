// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Telepathy Authors

package calico

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/frozenprocess/telepathy/api"
)

// TestDebugCase runs one e2e/testdata case through Evaluate() IN-PROCESS so a
// breakpoint in eval.go actually hits (the e2e harness execs the telepathy
// binary out-of-process, where breakpoints can't reach). It replicates the
// `telepathy test` subcommand: topology -> policies -> RunAssertions.
//
// Pick the case with CASE=<dir> (default calico-gnp-named-port-ingress); it must exist
// under e2e/testdata/. Debug it with the "debug provider/calico (eval.go)"
// launch config narrowed to -test.run TestDebugCase.
func TestDebugCase(t *testing.T) {
	name := os.Getenv("CASE")
	if name == "" {
		name = "calico-gnp-named-port-ingress"
	}
	dir := filepath.Join("..", "..", "e2e", "testdata", name)

	topo, err := os.ReadFile(filepath.Join(dir, "topology.yaml"))
	if err != nil {
		t.Fatalf("read topology: %v", err)
	}
	req, err := api.DecodeRequest(topo)
	if err != nil {
		t.Fatalf("decode topology: %v", err)
	}
	pol, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	req.Policies = append(req.Policies, api.ParsePolicyManifests(pol)...)

	assertData, err := os.ReadFile(filepath.Join(dir, "assertions.yaml"))
	if err != nil {
		t.Fatalf("read assertions: %v", err)
	}
	assertions, err := api.DecodeAssertions(assertData)
	if err != nil {
		t.Fatalf("decode assertions: %v", err)
	}

	report := api.RunAssertions(Evaluate, req, assertions) // <-- set a breakpoint in eval.go
	for _, r := range report.Results {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
		}
		t.Logf("%s  %s -> %s  expect=%s got=%s %s",
			status, r.Assertion.From, r.Assertion.To, r.Assertion.Expect, r.Got, r.Err)
	}
	if !report.Ok() {
		t.Errorf("%s: %d passed, %d failed", name, report.Passed, report.Failed)
	}
}
