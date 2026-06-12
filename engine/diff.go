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

package engine

import (
	"fmt"
	"sort"
	"strings"
)

// Change kinds for a single flow between a base and a head evaluation. The two
// that matter most for review are Opened (a path that was denied now allows —
// a new exposure) and Closed (a path that was allowed now denies — a possible
// outage). Added/Removed cover flows that appear or vanish because the topology
// itself changed (a pod added/removed); only the connectivity-bearing ones
// (head allows / base allowed) are surfaced, so adding one pod to a large
// topology doesn't bury the diff under hundreds of new deny pairs.
const (
	FlowOpened  = "opened"  // base deny  -> head allow
	FlowClosed  = "closed"  // base allow -> head deny
	FlowAdded   = "added"   // absent in base -> head allow
	FlowRemoved = "removed" // base allow -> absent in head
)

// FlowChange is one differing flow between two evaluations. Base/Head are the
// verdicts on each side ("allow"/"deny", or "" when the flow is absent on that
// side). From/To are the matrix endpoint ids.
type FlowChange struct {
	From string `json:"from"`
	To   string `json:"to"`
	Base string `json:"base"`
	Head string `json:"head"`
	Kind string `json:"kind"`
}

// Flow is the matrix key form, for display.
func (c FlowChange) Flow() string { return c.From + "->" + c.To }

// DiffReport is the result of comparing two connectivity matrices. Changes is
// the ordered list of differing flows (Opened first, then Closed, Removed,
// Added — most security-relevant first); the counters summarise it. Errors and
// Warnings carry the head evaluation's own findings so a PR comment can flag a
// policy that the change broke outright. Unchanged counts flows that compared
// equal (excluding the noise pairs DiffResponses intentionally drops).
type DiffReport struct {
	Changes   []FlowChange `json:"changes"`
	Opened    int          `json:"opened"`
	Closed    int          `json:"closed"`
	Added     int          `json:"added"`
	Removed   int          `json:"removed"`
	Unchanged int          `json:"unchanged"`
	Errors    []string     `json:"errors,omitempty"`
	Warnings  []string     `json:"warnings,omitempty"`
}

// Changed reports whether any flow differs between the two evaluations.
func (r DiffReport) Changed() bool { return len(r.Changes) > 0 }

// DiffResponses compares the head evaluation against the base and reports every
// connectivity change. A flow present on both sides with differing verdicts is
// Opened (deny->allow) or Closed (allow->deny). A flow present on only one side
// is reported only when it carries connectivity — head allows (Added) or base
// allowed (Removed) — so topology churn that merely adds denied pairs stays out
// of the diff. head.Errors/Warnings are forwarded onto the report.
func DiffResponses(base, head Response) DiffReport {
	report := DiffReport{Errors: head.Errors, Warnings: head.Warnings}

	// Union of flow keys across both matrices, processed in sorted order so the
	// pre-sort within a kind is deterministic before the final kind ordering.
	keys := make(map[string]struct{}, len(base.Matrix)+len(head.Matrix))
	for k := range base.Matrix {
		keys[k] = struct{}{}
	}
	for k := range head.Matrix {
		keys[k] = struct{}{}
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, k := range sorted {
		bv, inBase := base.Matrix[k]
		hv, inHead := head.Matrix[k]
		from, to := splitFlowKey(k)

		switch {
		case inBase && inHead:
			if bv == hv {
				report.Unchanged++
				continue
			}
			kind := FlowClosed // allow -> deny
			if bv == "deny" && hv == "allow" {
				kind = FlowOpened
				report.Opened++
			} else {
				report.Closed++
			}
			report.Changes = append(report.Changes, FlowChange{From: from, To: to, Base: bv, Head: hv, Kind: kind})
		case inHead && !inBase:
			if hv == "allow" { // a new reachable path; denied new pairs are noise
				report.Added++
				report.Changes = append(report.Changes, FlowChange{From: from, To: to, Base: "", Head: hv, Kind: FlowAdded})
			}
		case inBase && !inHead:
			if bv == "allow" { // a previously reachable path that vanished
				report.Removed++
				report.Changes = append(report.Changes, FlowChange{From: from, To: to, Base: bv, Head: "", Kind: FlowRemoved})
			}
		}
	}

	sort.SliceStable(report.Changes, func(i, j int) bool {
		ri, rj := kindRank(report.Changes[i].Kind), kindRank(report.Changes[j].Kind)
		if ri != rj {
			return ri < rj
		}
		return report.Changes[i].Flow() < report.Changes[j].Flow()
	})
	return report
}

// kindRank orders change kinds for display: Opened (new exposure) first, then
// Closed (possible outage), then the topology-churn kinds.
func kindRank(kind string) int {
	switch kind {
	case FlowOpened:
		return 0
	case FlowClosed:
		return 1
	case FlowRemoved:
		return 2
	case FlowAdded:
		return 3
	default:
		return 4
	}
}

// splitFlowKey splits a "src->dst" matrix key. A key without the separator
// (which Evaluate never emits) yields the whole string as From and an empty To.
func splitFlowKey(k string) (from, to string) {
	if i := strings.Index(k, "->"); i >= 0 {
		return k[:i], k[i+2:]
	}
	return k, ""
}

// FormatDiffMarkdown renders a DiffReport as a GitHub-flavoured Markdown
// comment: a headline summary, a changed-flows table, a legend, and any
// head-side policy errors/warnings. It is the artifact a CI step posts on a PR,
// so it is self-contained and reads cleanly even with zero changes.
func FormatDiffMarkdown(r DiffReport) string {
	var b strings.Builder
	b.WriteString("## 🔮 Telepathy — NetworkPolicy impact\n\n")

	if !r.Changed() {
		b.WriteString("✅ **No connectivity changes** — every evaluated flow is unchanged from the base.\n")
	} else {
		b.WriteString(diffSummaryLine(r))
		b.WriteString("\n\n| Change | Flow | Before | After |\n|---|---|---|---|\n")
		for _, c := range r.Changes {
			fmt.Fprintf(&b, "| %s | `%s` → `%s` | %s | %s |\n",
				changeBadge(c.Kind),
				c.From, c.To,
				verdictCell(c.Base, false),
				verdictCell(c.Head, true))
		}
		b.WriteString("\n<sub>🟠 opened = newly allowed · 🔴 closed = newly denied · ⚪ removed · 🟢 added</sub>\n")
	}

	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, "\n> ❌ **%d policy error(s)** in this revision:\n", len(r.Errors))
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "> - %s\n", e)
		}
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintf(&b, "\n> ⚠️ **%d warning(s)**:\n", len(r.Warnings))
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "> - %s\n", w)
		}
	}
	return b.String()
}

// diffSummaryLine is the one-line headline above the table, naming only the
// non-zero categories.
func diffSummaryLine(r DiffReport) string {
	parts := []string{}
	if r.Opened > 0 {
		parts = append(parts, fmt.Sprintf("🟠 %d opened", r.Opened))
	}
	if r.Closed > 0 {
		parts = append(parts, fmt.Sprintf("🔴 %d closed", r.Closed))
	}
	if r.Removed > 0 {
		parts = append(parts, fmt.Sprintf("⚪ %d removed", r.Removed))
	}
	if r.Added > 0 {
		parts = append(parts, fmt.Sprintf("🟢 %d added", r.Added))
	}
	return fmt.Sprintf("**%d flow(s) changed** — %s", len(r.Changes), strings.Join(parts, ", "))
}

// changeBadge is the table cell for a change kind.
func changeBadge(kind string) string {
	switch kind {
	case FlowOpened:
		return "🟠 opened"
	case FlowClosed:
		return "🔴 closed"
	case FlowRemoved:
		return "⚪ removed"
	case FlowAdded:
		return "🟢 added"
	default:
		return kind
	}
}

// verdictCell renders a before/after verdict; the absent side shows "—" and the
// head (after) verdict is bolded so the new state stands out.
func verdictCell(v string, head bool) string {
	if v == "" {
		return "—"
	}
	if head {
		return "**" + v + "**"
	}
	return v
}
