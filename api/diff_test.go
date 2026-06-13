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

package api

import "strings"
import "testing"

// TestDiffResponsesKinds: each change kind must be classified from the right
// base/head verdict pair, and equal flows must not appear. Opened (deny->allow)
// and closed (allow->deny) are the headline cases; a deny->deny flow is
// unchanged and must stay out of Changes.
func TestDiffResponsesKinds(t *testing.T) {
	base := Response{Matrix: map[string]string{
		"a->b": "allow", // -> deny  (closed)
		"a->c": "deny",  // -> allow (opened)
		"a->d": "allow", // unchanged
		"a->e": "allow", // removed in head
		"a->f": "deny",  // removed in head but base deny -> noise, dropped
	}}
	head := Response{Matrix: map[string]string{
		"a->b": "deny",
		"a->c": "allow",
		"a->d": "allow",
		"a->g": "allow", // added (new reachable path)
		"a->h": "deny",  // added but deny -> noise, dropped
	}}

	r := DiffResponses(base, head)
	if r.Opened != 1 || r.Closed != 1 || r.Added != 1 || r.Removed != 1 {
		t.Fatalf("counts: opened=%d closed=%d added=%d removed=%d (want 1/1/1/1): %+v",
			r.Opened, r.Closed, r.Added, r.Removed, r.Changes)
	}
	if r.Unchanged != 1 {
		t.Fatalf("unchanged=%d, want 1", r.Unchanged)
	}
	if len(r.Changes) != 4 {
		t.Fatalf("expected 4 changes, got %d: %+v", len(r.Changes), r.Changes)
	}
	// Opened must sort ahead of closed.
	if r.Changes[0].Kind != FlowOpened || r.Changes[1].Kind != FlowClosed {
		t.Fatalf("ordering wrong: %s then %s", r.Changes[0].Kind, r.Changes[1].Kind)
	}
	// The noise pairs must be absent.
	for _, c := range r.Changes {
		if c.Flow() == "a->f" || c.Flow() == "a->h" {
			t.Fatalf("denied churn pair %s leaked into the diff", c.Flow())
		}
	}
}

// TestDiffResponsesNoChange: identical matrices yield no changes and Changed()
// is false — the empty-diff path the PR comment renders as "no changes".
func TestDiffResponsesNoChange(t *testing.T) {
	m := map[string]string{"a->b": "allow", "a->c": "deny"}
	r := DiffResponses(Response{Matrix: m}, Response{Matrix: m})
	if r.Changed() {
		t.Fatalf("expected no changes, got %+v", r.Changes)
	}
}

// TestFormatDiffMarkdown: the comment must name the changed flow and surface a
// head-side policy error, since a PR that breaks a policy outright is the case
// reviewers most need flagged.
func TestFormatDiffMarkdown(t *testing.T) {
	base := Response{Matrix: map[string]string{"x/app->x/db": "deny"}}
	head := Response{Matrix: map[string]string{"x/app->x/db": "allow"}, Errors: []string{"policy bad-pol: unsupported field"}}
	md := FormatDiffMarkdown(DiffResponses(base, head))

	for _, want := range []string{"opened", "`x/app` → `x/db`", "policy error", "unsupported field"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q:\n%s", want, md)
		}
	}

	empty := FormatDiffMarkdown(DiffResponses(base, base))
	if !strings.Contains(empty, "No connectivity changes") {
		t.Fatalf("empty diff should say no changes:\n%s", empty)
	}
}
