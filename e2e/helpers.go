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
	"sort"
	"strings"
)

// Small formatting and collection helpers shared across the harness. Each is a
// pure function with no cluster or test-state dependency, gathered here so callers
// (report rendering, diagnostics, manifest building) don't each re-roll them.

// cmdErr wraps a failed CLI invocation (kubectl/docker) in the harness's standard
// error shape — "<action>: <err>\n<combined output>" — so every cluster operation
// reports a failure the same way: what we tried, what the OS/exec layer said, and
// what the tool printed. It returns nil when err is nil, so a call site can write
// `return cmdErr(action, out, err)` without its own nil guard.
func cmdErr(action, out string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %v\n%s", action, err, out)
}

// writeKubectlSection appends one titled block to a diagnostics dump: a
// "=== title ===" header, a "(kubectl error: …)" line when err is non-nil, the
// command output, and a trailing blank line — normalizing the output's final
// newline so sections always stay one blank line apart. clusterStateDump and
// policyDump share this exact shape.
func writeKubectlSection(b *strings.Builder, title, out string, err error) {
	fmt.Fprintf(b, "=== %s ===\n", title)
	if err != nil {
		fmt.Fprintf(b, "(kubectl error: %v)\n", err)
	}
	b.WriteString(out)
	if !strings.HasSuffix(out, "\n") {
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
}

// sortedMapKeys returns a string map's keys in deterministic (sorted) order.
func sortedMapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedKeys returns a set's keys in deterministic order — used to render the
// namespace list in log messages without depending on map iteration order.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedValues returns a string map's values in deterministic order.
func sortedValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// sanitizeName makes a case name safe to use as a single path segment. Case names
// are already simple (kebab-case dir names), so this is just a guard.
func sanitizeName(name string) string {
	return strings.NewReplacer("/", "_", " ", "_").Replace(name)
}

// dash renders an empty string as "-", for table cells that have no value.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// firstLine returns the first line of s (everything before the first newline), or
// s unchanged when it has no newline — for collapsing a multi-line error into a
// one-line table cell.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
