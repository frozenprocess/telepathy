// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 The Telepathy Authors
//
// This file is part of Telepathy.
//
// Telepathy is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License version 3 as published
// by the Free Software Foundation.
//
// Telepathy is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.

package engine

import (
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// Assertion is one expected-connectivity claim a caller wants to gate on: a
// flow From->To at (Port, Protocol) that must evaluate to Expect ("allow" or
// "deny"). It is the unit of a Telepathy test file — the thing that turns the
// connectivity matrix from a report into a pass/fail CI check.
//
// Port/Protocol are optional: when zero/empty they inherit the enclosing
// Request's probe (which itself defaults to 8080/tcp), so a test file that
// only cares about one port can omit them everywhere. Name is a free-text
// label echoed back in the result so a failure reads like a test case
// ("frontend must reach backend") rather than a pair of IDs.
type Assertion struct {
	Name     string `json:"name,omitempty"`
	From     string `json:"from"`
	To       string `json:"to"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Expect   string `json:"expect"`
}

// AssertionFile is the on-disk form a caller writes (telepathy.tests.yaml). It
// accepts either a bare YAML list of assertions or an object with an
// `assertions:` key — DecodeAssertions handles both — so the file can grow
// top-level options later without breaking the simple list form.
type AssertionFile struct {
	Assertions []Assertion `json:"assertions"`
}

// AssertionResult is the outcome of checking one Assertion against an evaluated
// matrix. Pass is true iff the flow was found and Got == Expect. Got is the
// matrix verdict ("allow"/"deny", or "" when the flow wasn't in the matrix);
// Err is set for a malformed assertion or an unknown From->To pair, which counts
// as a failure distinct from a wrong verdict.
type AssertionResult struct {
	Assertion Assertion `json:"assertion"`
	Got       string    `json:"got"`
	Pass      bool      `json:"pass"`
	Err       string    `json:"err,omitempty"`
}

// AssertionReport is the full result of RunAssertions: every per-assertion
// result plus pass/fail counts and the engine's own errors/warnings (surfaced
// once across all probe groups, deduplicated). Ok reports whether every
// assertion passed — the bit a CLI turns into its exit code.
type AssertionReport struct {
	Results  []AssertionResult `json:"results"`
	Passed   int               `json:"passed"`
	Failed   int               `json:"failed"`
	Errors   []string          `json:"errors,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
}

// Ok reports whether every assertion passed (and at least one ran). A report
// with zero assertions is not Ok — an empty test file is a mistake, not a pass.
func (r AssertionReport) Ok() bool {
	return r.Failed == 0 && r.Passed > 0
}

// DecodeAssertions parses a test file (JSON or YAML, via sigs.k8s.io/yaml) into
// a slice of Assertions. It accepts both the bare-list form
//
//	- {from: a, to: b, expect: allow}
//
// and the wrapped form
//
//	assertions:
//	  - {from: a, to: b, expect: allow}
//
// Empty input is an error here (unlike DecodeRequest) — running the test
// command with nothing to assert is a usage mistake worth surfacing.
func DecodeAssertions(data []byte) ([]Assertion, error) {
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("empty assertions file: nothing to test")
	}
	// Try the bare-list form first; sigs.k8s.io/yaml routes YAML through JSON,
	// so a leading `-`/`[` lands as a JSON array and a mapping as an object.
	var list []Assertion
	if err := yaml.Unmarshal(data, &list); err == nil && len(list) > 0 {
		return list, nil
	}
	var file AssertionFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode assertions: %w", err)
	}
	if len(file.Assertions) == 0 {
		return nil, fmt.Errorf("no assertions found: expected a list or an `assertions:` key")
	}
	return file.Assertions, nil
}

// RunAssertions evaluates req's topology against the given assertions and
// reports which held. Because the connectivity matrix is computed for a single
// (port, protocol) probe, assertions are grouped by their effective probe —
// each distinct (port, protocol) triggers exactly one Evaluate over a clone of
// req, so a test file spanning many ports stays correct without N full sweeps
// per assertion. Engine errors/warnings are collected across groups and
// deduplicated.
//
// req is not mutated; each group runs on a shallow copy with Port/Protocol
// overridden (the slices are shared read-only, which Evaluate never writes).
func RunAssertions(req Request, assertions []Assertion) AssertionReport {
	var report AssertionReport
	report.Results = make([]AssertionResult, len(assertions))

	// probeKey identifies one Evaluate sweep; idxByProbe gathers the original
	// assertion indices that share it so results land back in input order.
	type probeKey struct {
		port  int
		proto string
	}
	idxByProbe := map[probeKey][]int{}
	seenErr := map[string]bool{}
	seenWarn := map[string]bool{}

	for i, a := range assertions {
		if res, bad := validateAssertion(a); bad {
			report.Results[i] = res
			continue
		}
		k := probeKey{port: effectivePort(a, req), proto: effectiveProto(a, req)}
		idxByProbe[k] = append(idxByProbe[k], i)
	}

	// Stable probe order: by port then protocol, so DEBUG output / any future
	// streaming is deterministic regardless of map iteration.
	probes := make([]probeKey, 0, len(idxByProbe))
	for k := range idxByProbe {
		probes = append(probes, k)
	}
	sort.Slice(probes, func(i, j int) bool {
		if probes[i].port != probes[j].port {
			return probes[i].port < probes[j].port
		}
		return probes[i].proto < probes[j].proto
	})

	for _, k := range probes {
		probeReq := req
		probeReq.Port = k.port
		probeReq.Protocol = k.proto
		resp := Evaluate(probeReq)

		for _, e := range resp.Errors {
			if !seenErr[e] {
				seenErr[e] = true
				report.Errors = append(report.Errors, e)
			}
		}
		for _, w := range resp.Warnings {
			if !seenWarn[w] {
				seenWarn[w] = true
				report.Warnings = append(report.Warnings, w)
			}
		}

		for _, i := range idxByProbe[k] {
			report.Results[i] = checkAssertion(assertions[i], resp.Matrix)
		}
	}

	for _, r := range report.Results {
		if r.Pass {
			report.Passed++
		} else {
			report.Failed++
		}
	}
	return report
}

// validateAssertion rejects a structurally invalid assertion before it reaches
// the evaluator, returning a failed result and bad=true. From/To are required
// and Expect must normalise to allow/deny.
func validateAssertion(a Assertion) (AssertionResult, bool) {
	if strings.TrimSpace(a.From) == "" || strings.TrimSpace(a.To) == "" {
		return AssertionResult{Assertion: a, Err: "assertion missing `from` or `to`"}, true
	}
	switch strings.ToLower(strings.TrimSpace(a.Expect)) {
	case "allow", "deny":
		return AssertionResult{}, false
	default:
		return AssertionResult{Assertion: a, Err: fmt.Sprintf("assertion `expect` must be allow|deny, got %q", a.Expect)}, true
	}
}

// checkAssertion looks the From->To flow up in an evaluated matrix and compares
// it to Expect (case-insensitively). A flow absent from the matrix is a failure
// with a clear Err — almost always a typo in an endpoint ID — rather than a
// silent mismatch.
func checkAssertion(a Assertion, matrix map[string]string) AssertionResult {
	got, ok := matrix[a.From+"->"+a.To]
	if !ok {
		return AssertionResult{
			Assertion: a,
			Err:       fmt.Sprintf("no flow %s->%s in matrix (check endpoint ids)", a.From, a.To),
		}
	}
	return AssertionResult{
		Assertion: a,
		Got:       got,
		Pass:      got == strings.ToLower(strings.TrimSpace(a.Expect)),
	}
}

// effectivePort resolves the probe port for an assertion: its own Port, else
// the Request's, else the engine default (8080) — mirroring Evaluate's default
// so grouping keys match what Evaluate actually probes.
func effectivePort(a Assertion, req Request) int {
	if a.Port != 0 {
		return a.Port
	}
	if req.Port != 0 {
		return req.Port
	}
	return 8080
}

// effectiveProto resolves the probe protocol the same way (default tcp).
func effectiveProto(a Assertion, req Request) string {
	if a.Protocol != "" {
		return a.Protocol
	}
	if req.Protocol != "" {
		return req.Protocol
	}
	return "tcp"
}
