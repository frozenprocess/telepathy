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

package e2e

import (
	"fmt"
	"strings"
)

// row is one assertion's three-way outcome: the authored expectation, the
// engine's prediction, and the cluster's measured verdict.
type row struct {
	from, to       string
	port           int
	proto          string
	expect         string // authored ground truth
	engine         string // telepathy verdict ("" if the engine had no flow)
	cluster        string // measured dataplane verdict ("" if the probe errored)
	clusterOut     string // raw probe output (agnhost connect / ping) that produced the verdict
	probeErr       string // harness-level probe failure, if any
	quarantined    string // non-empty => flow not testable on the cluster (reason); excluded from scoring
	engineMismatch bool   // engine != cluster — the fatal condition
	expectMismatch bool   // cluster != expect — informational
}

// caseReport accumulates the rows for one e2e/testdata case and renders them.
type caseReport struct {
	name string
	rows []row
}

func (r *caseReport) add(rw row) {
	if rw.quarantined == "" {
		rw.engineMismatch = rw.probeErr == "" && rw.engine != rw.cluster
		rw.expectMismatch = rw.probeErr == "" && rw.cluster != "" && rw.cluster != strings.ToLower(strings.TrimSpace(rw.expect))
	}
	r.rows = append(r.rows, rw)
}

// mismatches counts the fatal rows: engine≠cluster disagreements and probe
// errors. Quarantined rows are excluded — they're known-not-testable here.
func (r *caseReport) mismatches() int {
	n := 0
	for _, rw := range r.rows {
		if rw.quarantined != "" {
			continue
		}
		if rw.engineMismatch || rw.probeErr != "" {
			n++
		}
	}
	return n
}

// render produces a fixed-width table. A row is flagged "DIFF" when the engine
// and the cluster disagree (the failure), "expect?" when both agree with each
// other but not with the authored expectation (a questionable assertion), and
// "ERR" when the probe itself failed.
func (r *caseReport) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "case %s\n", r.name)
	fmt.Fprintf(&b, "  %-22s %-22s %-5s %-5s %-7s %-7s %-7s %s\n",
		"FROM", "TO", "PORT", "PROTO", "EXPECT", "ENGINE", "CLUSTER", "VERDICT")
	for _, rw := range r.rows {
		verdict := "ok"
		switch {
		case rw.quarantined != "":
			verdict = "QUARANTINED: " + firstLine(rw.quarantined)
		case rw.probeErr != "":
			verdict = "ERR: " + firstLine(rw.probeErr)
		case rw.engineMismatch:
			verdict = "DIFF (engine != cluster)"
		case rw.expectMismatch:
			verdict = "expect? (engine==cluster, != expect)"
		}
		fmt.Fprintf(&b, "  %-22s %-22s %-5s %-5s %-7s %-7s %-7s %s\n",
			rw.from, rw.to, portStr(rw.port), rw.proto, rw.expect, dash(rw.engine), dash(rw.cluster), verdict)
	}
	if d := r.details(); d != "" {
		b.WriteString("\n  probe output (failed rows):\n")
		b.WriteString(d)
	}
	return b.String()
}

// details returns the captured probe output for the rows that failed — DIFF
// (engine != cluster) and ERR (the probe itself errored) — so a reader can see
// what the dataplane actually said, not just the allow/deny verdict it was
// reduced to. The table throws that away; on a failure it's the first thing you
// want. Empty when no row failed.
func (r *caseReport) details() string {
	var b strings.Builder
	for _, rw := range r.rows {
		if rw.quarantined != "" || (!rw.engineMismatch && rw.probeErr == "") {
			continue
		}
		if rw.port == 0 {
			fmt.Fprintf(&b, "  --- %s -> %s (%s) ---\n", rw.from, rw.to, rw.proto)
		} else {
			fmt.Fprintf(&b, "  --- %s -> %s (%s/%d) ---\n", rw.from, rw.to, rw.proto, rw.port)
		}
		if rw.probeErr != "" {
			fmt.Fprintf(&b, "    probe error: %s\n", rw.probeErr)
		}
		out := strings.TrimSpace(rw.clusterOut)
		if out == "" {
			out = "(no probe output captured)"
		}
		for _, line := range strings.Split(out, "\n") {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
	return b.String()
}
