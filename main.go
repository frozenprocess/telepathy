// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Telepathy Authors
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

// Command telepathy is an in-process evaluator for Kubernetes/Calico
// network policies. Given a topology (endpoints + namespaces) and one or more
// policy manifests, it computes the pod-to-pod connectivity matrix WITHOUT a
// cluster, by reusing Calico's own code (libcalico-go conversion /
// updateprocessors, felix/calc CalculationGraph, app-policy/checker.Evaluate).
//
// Protocol: a Request on stdin, a JSON Response (connectivity matrix) on
// stdout. The stdin Request may be JSON or YAML (auto-detected). A pod pair is
// "allow" iff it clears BOTH the source's egress and the destination's ingress
// (how a real packet must pass).
//
// Input flags (shared by every subcommand):
//
//	-policy FILE|DIR   read raw policy manifest(s) — plain Kubernetes/Calico
//	                   YAML, multi-document (---) supported, flavor auto-detected
//	                   from apiVersion — and append them to the stdin Request.
//	                   Repeatable; a directory pulls in its *.yaml / *.yml.
//	                   Topology (endpoints, namespaces, …) still comes from stdin.
//
// Subcommands:
//
//	telepathy            evaluate connectivity (default; Request in,
//	                         JSON Response out — the harness contract).
//	telepathy test       gate a topology against a connectivity test file
//	                         (-assert FILE): each {from,to,expect} flow is
//	                         checked and the command exits non-zero if any
//	                         assertion fails — the CI contract. -json emits the
//	                         structured AssertionReport instead of TAP-ish text.
//	telepathy diff       compare two evaluate Responses (BASE.json HEAD.json)
//	                         and report the flows that changed — opened
//	                         (deny->allow), closed (allow->deny), added, removed.
//	                         -format markdown emits a PR-comment table; -json the
//	                         structured DiffReport. With -exit-code, exits non-zero
//	                         when any flow changed (git diff --exit-code style).
//	telepathy iptables   render the iptables/nftables chains Felix would
//	                         program for the same Request. Text output by
//	                         default; -json for the structured form.
//	telepathy bpf        render the eBPF policy program Felix would
//	                         JIT-assemble per endpoint+direction for the same
//	                         Request (annotated disassembly).
//	telepathy version    print the engine version, the pinned Calico
//	                         version it is built against, and its capabilities
//	                         (also reachable as --version / -version).
//
// The vendor-neutral request/response schema lives in the importable ./api
// package; each CNI's policy engine lives behind the provider.Provider
// interface in ./provider (the Calico engine in ./provider/calico). This binary
// is a CLI shim that selects a provider (-provider, default calico) and calls
// Provider.Evaluate / the provider's dataplane renderers, so callers like the
// policy_llm harness keep working unchanged. Servers that want to avoid
// per-request fork/exec can import ./api + ./provider/calico directly.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	logrus "github.com/sirupsen/logrus"

	"github.com/frozenprocess/telepathy/api"
	"github.com/frozenprocess/telepathy/provider"
	"github.com/frozenprocess/telepathy/provider/calico"
)

// dataplaneRenderer is the optional capability the iptables/bpf/hns subcommands
// require. Its types are Calico-specific (Felix renders iptables/nftables/bpf/
// hns; another CNI would render its own dataplane), so the interface lives here
// in the CLI rather than in the provider package, and the selected provider is
// type-asserted against it.
type dataplaneRenderer interface {
	RenderIptables(api.Request, calico.IptablesOptions) calico.IptablesResponse
	RenderBPF(api.Request, calico.BPFOptions) calico.BPFResponse
	RenderHNS(api.Request, calico.HNSOptions) calico.HNSResponse
}

// mustProvider resolves a registered provider by name or exits with a usage
// error listing the available providers.
func mustProvider(name string) provider.Provider {
	p, ok := provider.Get(name)
	if !ok {
		fail("unknown -provider %q (have: %s)", name, strings.Join(provider.List(), ", "))
	}
	return p
}

// mustDataplaneRenderer resolves the provider and asserts it can render
// dataplane artifacts, failing cleanly when it cannot.
func mustDataplaneRenderer(name string) dataplaneRenderer {
	p := mustProvider(name)
	dr, ok := p.(dataplaneRenderer)
	if !ok {
		fail("provider %q does not render dataplane artifacts", name)
	}
	return dr
}

// Build metadata. The defaults keep `--version` meaningful for a plain
// `go build .` / `go run .`; the Makefile overrides them via -ldflags so a
// released binary reports its real commit, build date, and pinned Calico tag.
//
//	go build -ldflags "\
//	  -X main.engineVersion=v0.1.0 \
//	  -X main.calicoVersion=v3.32.0 \
//	  -X main.gitCommit=$(git rev-parse --short HEAD) \
//	  -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" .
var (
	// engineVersion is the telepathy binary's own version.
	engineVersion = "dev"
	// calicoVersion is the Calico source tree the engine is built against
	// (the pinned tag in third_party/calico — see Makefile CALICO_VERSION).
	calicoVersion = "v3.32.0"
	// gitCommit / buildDate are stamped at build time; "unknown" otherwise.
	gitCommit = "unknown"
	buildDate = "unknown"
)

// capability describes one thing the engine can do, surfaced by --version so a
// caller can discover the feature set without scraping the help text.
type capability struct {
	name, desc string
}

var capabilities = []capability{
	{"evaluate", "pod-to-pod connectivity matrix (default; Request in, JSON Response out)"},
	{"test", "gate a topology against a connectivity assertions file (non-zero exit on failure)"},
	{"diff", "compare two evaluate Responses and report opened/closed/added/removed flows (PR-comment markdown)"},
	{"iptables", "render the iptables/nftables chains Felix would program"},
	{"bpf", "render the eBPF policy program Felix would JIT-assemble per endpoint/direction"},
	{"hns", "render the Windows HNS ACL rules Felix would program per endpoint/direction"},
}

// printVersion writes the version banner and capability list to stdout. It is
// reached by the top-level `version` subcommand and the `--version`/`-version`
// flags.
func printVersion() {
	fmt.Printf("telepathy %s\n", engineVersion)
	fmt.Printf("  built against Calico %s\n", calicoVersion)
	fmt.Printf("  go      %s\n", runtime.Version())
	fmt.Printf("  commit  %s\n", gitCommit)
	fmt.Printf("  built   %s\n", buildDate)
	fmt.Println()
	fmt.Println("Capabilities:")
	for _, c := range capabilities {
		fmt.Printf("  %-9s %s\n", c.name, c.desc)
	}
}

// isVersionArg reports whether s requests the version banner.
func isVersionArg(s string) bool {
	return s == "version" || s == "--version" || s == "-version" || s == "-v"
}

func main() {
	if os.Getenv("POLICY_ENGINE_DEBUG") == "" {
		logrus.SetLevel(logrus.ErrorLevel)
	}

	// Subcommand dispatch. Default (no subcommand) preserves the original
	// "JSON Request in -> JSON Response out" contract the harness depends on.
	// version is handled before the others so it never blocks on stdin.
	if len(os.Args) > 1 && isVersionArg(os.Args[1]) {
		printVersion()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "iptables" {
		runIptables(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "bpf" {
		runBPF(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "hns" {
		runHNS(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "test" {
		runTest(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "diff" {
		runDiff(os.Args[2:])
		return
	}

	fs := flag.NewFlagSet("telepathy", flag.ExitOnError)
	policies, prov := addRequestFlags(fs)
	_ = fs.Parse(os.Args[1:])

	p := mustProvider(*prov)
	req := loadRequest(*policies)
	resp := p.Evaluate(req)
	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		fail("encode response: %v", err)
	}
}

// stringSlice collects a repeatable flag (e.g. -policy a.yaml -policy b.yaml).
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// addRequestFlags registers the input flags shared by every subcommand and
// returns the slice the -policy values land in plus the selected -provider
// name (default "calico"). -provider chooses which CNI engine evaluates the
// Request; the default preserves the original Calico-only behaviour.
func addRequestFlags(fs *flag.FlagSet) (*stringSlice, *string) {
	var policies stringSlice
	fs.Var(&policies, "policy", "raw policy manifest YAML file or directory to append to the stdin Request (repeatable)")
	prov := fs.String("provider", "calico", "CNI policy engine to evaluate with (e.g. calico)")
	return &policies, prov
}

// loadRequest builds the Request: decode stdin (JSON or YAML, when piped), then
// append every policy parsed from the -policy files/directories. Stdin and
// -policy compose — stdin carries the topology, -policy adds manifests — but
// either may be omitted.
func loadRequest(policyPaths []string) api.Request {
	data, err := readPipedStdin()
	if err != nil {
		fail("read stdin: %v", err)
	}
	req, err := api.DecodeRequest(data)
	if err != nil {
		fail("%v", err)
	}
	for _, p := range policyPaths {
		files, err := expandPolicyPath(p)
		if err != nil {
			fail("%v", err)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				fail("read policy %s: %v", f, err)
			}
			req.Policies = append(req.Policies, api.ParsePolicyManifests(b)...)
		}
	}
	return req
}

// readPipedStdin reads all of stdin when it is piped/redirected, and returns
// nil when stdin is an interactive terminal — so a -policy-only invocation
// doesn't block waiting for a Request that will never arrive.
func readPipedStdin() ([]byte, error) {
	st, err := os.Stdin.Stat()
	if err == nil && st.Mode()&os.ModeCharDevice != 0 {
		return nil, nil // terminal: no piped Request
	}
	return io.ReadAll(os.Stdin)
}

// expandPolicyPath resolves a -policy argument to the YAML files it names: the
// file itself, or every *.yaml / *.yml in it when it is a directory (sorted, as
// os.ReadDir returns names sorted).
func expandPolicyPath(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("policy path %s: %w", path, err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read policy dir %s: %w", path, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name := e.Name(); strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, filepath.Join(path, name))
		}
	}
	return files, nil
}

// runIptables implements `telepathy iptables`: read the same JSON Request
// from stdin, render the dataplane chains, print them.
func runIptables(args []string) {
	fs := flag.NewFlagSet("iptables", flag.ExitOnError)
	backend := fs.String("backend", "iptables", "dataplane to render: iptables | nftables | both")
	ipv := fs.String("ipversion", "", "IP version(s) to render: 4 | 6 | both (default: inferred from endpoints)")
	noStatic := fs.Bool("no-static", false, "omit Felix's static top-level chains (cali-INPUT/FORWARD/OUTPUT); show only policy/endpoint/profile chains")
	asJSON := fs.Bool("json", false, "emit the structured JSON response instead of text")
	policies, prov := addRequestFlags(fs)
	_ = fs.Parse(args)

	dr := mustDataplaneRenderer(*prov)
	req := loadRequest(*policies)

	opts := calico.IptablesOptions{IncludeStatic: !*noStatic}
	switch *backend {
	case "both":
		opts.Backends = []string{"iptables", "nftables"}
	case "iptables", "nftables":
		opts.Backends = []string{*backend}
	default:
		fail("unknown -backend %q (want iptables|nftables|both)", *backend)
	}
	switch *ipv {
	case "":
		// inferred by RenderIptables
	case "both":
		opts.IPVersions = []int{4, 6}
	case "4":
		opts.IPVersions = []int{4}
	case "6":
		opts.IPVersions = []int{6}
	default:
		fail("unknown -ipversion %q (want 4|6|both)", *ipv)
	}

	resp := dr.RenderIptables(req, opts)

	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
			fail("encode response: %v", err)
		}
		return
	}
	fmt.Print(formatIptables(resp))
}

// formatIptables renders the response as human-readable text: an
// `iptables-restore`-style block per (backend, ipVersion), warnings/errors
// surfaced as comments at the top.
func formatIptables(resp calico.IptablesResponse) string {
	var b strings.Builder
	for _, w := range resp.Warnings {
		fmt.Fprintf(&b, "# WARNING: %s\n", w)
	}
	for _, e := range resp.Errors {
		fmt.Fprintf(&b, "# ERROR: %s\n", e)
	}
	for _, dp := range resp.Dataplanes {
		fmt.Fprintf(&b, "\n# ===== %s (IPv%d) =====\n", dp.Backend, dp.IPVersion)
		for _, t := range dp.Tables {
			fmt.Fprintf(&b, "*%s\n", t.Table)
			for _, c := range t.Chains {
				for _, line := range c.Lines {
					b.WriteString(line)
					b.WriteByte('\n')
				}
			}
			b.WriteString("COMMIT\n")
		}
	}
	return b.String()
}

// runBPF implements `telepathy bpf`: read the same JSON Request from
// stdin, render each endpoint's eBPF policy program, print the annotated
// disassembly. Renders all endpoints + both directions by default; -endpoint
// and -direction narrow that.
func runBPF(args []string) {
	fs := flag.NewFlagSet("bpf", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "only render endpoints whose ID contains this substring (default: all)")
	dir := fs.String("direction", "both", "direction(s) to render: ingress | egress | both")
	ipv := fs.String("ipversion", "", "IP version(s) to render: 4 | 6 | both (default: inferred from endpoints)")
	asJSON := fs.Bool("json", false, "emit the structured JSON response instead of text")
	policies, prov := addRequestFlags(fs)
	_ = fs.Parse(args)

	dr := mustDataplaneRenderer(*prov)
	req := loadRequest(*policies)

	var opts calico.BPFOptions
	if *endpoint != "" {
		opts.Endpoints = []string{*endpoint}
	}
	switch *dir {
	case "both":
		opts.Directions = []string{"ingress", "egress"}
	case "ingress", "egress":
		opts.Directions = []string{*dir}
	default:
		fail("unknown -direction %q (want ingress|egress|both)", *dir)
	}
	switch *ipv {
	case "":
		// inferred by RenderBPF
	case "both":
		opts.IPVersions = []int{4, 6}
	case "4":
		opts.IPVersions = []int{4}
	case "6":
		opts.IPVersions = []int{6}
	default:
		fail("unknown -ipversion %q (want 4|6|both)", *ipv)
	}

	resp := dr.RenderBPF(req, opts)

	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
			fail("encode response: %v", err)
		}
		return
	}
	fmt.Print(formatBPF(resp))
}

// formatBPF renders the response as text: one annotated program block per
// (endpoint, direction, ipVersion).
func formatBPF(resp calico.BPFResponse) string {
	var b strings.Builder
	for _, w := range resp.Warnings {
		fmt.Fprintf(&b, "# WARNING: %s\n", w)
	}
	for _, e := range resp.Errors {
		fmt.Fprintf(&b, "# ERROR: %s\n", e)
	}
	if len(resp.Programs) == 0 {
		b.WriteString("# no endpoints matched\n")
	}
	for _, p := range resp.Programs {
		fmt.Fprintf(&b, "\n# ===== %s  (%s iface=%s, IPv%d", p.Endpoint, p.Direction, p.Interface, p.IPVersion)
		if p.SubPrograms > 1 {
			fmt.Fprintf(&b, ", %d sub-programs", p.SubPrograms)
		}
		b.WriteString(") =====\n")
		if p.Error != "" {
			fmt.Fprintf(&b, "# ERROR: %s\n", p.Error)
		}
		for _, line := range p.Lines {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// runHNS implements `telepathy hns`: read the same JSON Request from
// stdin, render each endpoint's Windows HNS ACL list, print it. Renders all
// endpoints + both directions by default; -endpoint and -direction narrow that.
// HNS is IPv4-only, so there is no -ipversion flag.
func runHNS(args []string) {
	fs := flag.NewFlagSet("hns", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "only render endpoints whose ID contains this substring (default: all)")
	dir := fs.String("direction", "both", "direction(s) to render: ingress | egress | both")
	asJSON := fs.Bool("json", false, "emit the structured JSON response instead of text")
	policies, prov := addRequestFlags(fs)
	_ = fs.Parse(args)

	dr := mustDataplaneRenderer(*prov)
	req := loadRequest(*policies)

	var opts calico.HNSOptions
	if *endpoint != "" {
		opts.Endpoints = []string{*endpoint}
	}
	switch *dir {
	case "both":
		opts.Directions = []string{"ingress", "egress"}
	case "ingress", "egress":
		opts.Directions = []string{*dir}
	default:
		fail("unknown -direction %q (want ingress|egress|both)", *dir)
	}

	resp := dr.RenderHNS(req, opts)

	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
			fail("encode response: %v", err)
		}
		return
	}
	fmt.Print(formatHNS(resp))
}

// formatHNS renders the response as text: one ACL block per (endpoint,
// direction), each rule on its own line in priority order.
func formatHNS(resp calico.HNSResponse) string {
	var b strings.Builder
	for _, w := range resp.Warnings {
		fmt.Fprintf(&b, "# WARNING: %s\n", w)
	}
	for _, e := range resp.Errors {
		fmt.Fprintf(&b, "# ERROR: %s\n", e)
	}
	if len(resp.Endpoints) == 0 {
		b.WriteString("# no endpoints matched\n")
	}
	for _, ep := range resp.Endpoints {
		fmt.Fprintf(&b, "\n# ===== %s  (%s iface=%s, IPv%d) =====\n",
			ep.Endpoint, ep.Direction, ep.Interface, ep.IPVersion)
		if ep.Error != "" {
			fmt.Fprintf(&b, "# ERROR: %s\n", ep.Error)
		}
		if len(ep.Rules) == 0 {
			b.WriteString("# (no rules)\n")
		}
		for _, r := range ep.Rules {
			b.WriteString(formatHNSRule(r))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// formatHNSRule renders one ACL rule as an aligned key=value line, omitting
// empty match fields. Protocol 256 is HNS's "any".
func formatHNSRule(r calico.HNSRule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  [%5d] %-5s %-6s", r.Priority, r.Action, r.Direction)
	if r.Protocol == 256 {
		b.WriteString(" proto=any")
	} else {
		fmt.Fprintf(&b, " proto=%d", r.Protocol)
	}
	if r.RemoteAddresses != "" {
		fmt.Fprintf(&b, " remoteAddr=%s", r.RemoteAddresses)
	}
	if r.LocalAddresses != "" {
		fmt.Fprintf(&b, " localAddr=%s", r.LocalAddresses)
	}
	if r.RemotePorts != "" {
		fmt.Fprintf(&b, " remotePorts=%s", r.RemotePorts)
	}
	if r.LocalPorts != "" {
		fmt.Fprintf(&b, " localPorts=%s", r.LocalPorts)
	}
	if r.RuleType != "" && r.RuleType != "Switch" {
		fmt.Fprintf(&b, " ruleType=%s", r.RuleType)
	}
	if r.ID != "" {
		fmt.Fprintf(&b, "  # %s", r.ID)
	}
	return b.String()
}

// runTest implements `telepathy test`: read the same JSON/YAML Request
// from stdin (topology) plus any -policy manifests, then check every assertion
// in the -assert file against the evaluated connectivity matrix. Prints a
// per-assertion pass/fail list and exits 1 if any assertion fails — the bit a
// CI step keys off. -json emits the structured api.AssertionReport instead.
func runTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	assertPath := fs.String("assert", "", "connectivity test file (YAML/JSON: a list of {from,to,expect[,port,protocol,name]}, or an `assertions:` key)")
	asJSON := fs.Bool("json", false, "emit the structured JSON AssertionReport instead of text")
	policies, prov := addRequestFlags(fs)
	_ = fs.Parse(args)

	if *assertPath == "" {
		fail("test: -assert FILE is required")
	}
	assertData, err := os.ReadFile(*assertPath)
	if err != nil {
		fail("read assertions %s: %v", *assertPath, err)
	}
	assertions, err := api.DecodeAssertions(assertData)
	if err != nil {
		fail("%v", err)
	}

	p := mustProvider(*prov)
	req := loadRequest(*policies)
	report := api.RunAssertions(p.Evaluate, req, assertions)

	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			fail("encode report: %v", err)
		}
		if !report.Ok() {
			os.Exit(1)
		}
		return
	}

	fmt.Print(formatAssertionReport(report))
	if !report.Ok() {
		os.Exit(1)
	}
}

// formatAssertionReport renders the report as a human- and grep-friendly list:
// one `PASS`/`FAIL` line per assertion (with the expected vs. got verdict),
// engine errors/warnings as comments, and a closing summary line.
func formatAssertionReport(r api.AssertionReport) string {
	var b strings.Builder
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "# WARNING: %s\n", w)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "# ERROR: %s\n", e)
	}
	for _, res := range r.Results {
		status := "PASS"
		if !res.Pass {
			status = "FAIL"
		}
		a := res.Assertion
		label := a.Name
		if label == "" {
			label = fmt.Sprintf("%s -> %s", a.From, a.To)
		}
		fmt.Fprintf(&b, "%s  %s", status, label)
		if a.Name != "" {
			fmt.Fprintf(&b, "  (%s -> %s)", a.From, a.To)
		}
		if res.Err != "" {
			fmt.Fprintf(&b, "  [%s]", res.Err)
		} else {
			fmt.Fprintf(&b, "  expect=%s got=%s", strings.ToLower(strings.TrimSpace(a.Expect)), res.Got)
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "\n%d passed, %d failed\n", r.Passed, r.Failed)
	return b.String()
}

// runDiff implements `telepathy diff BASE.json HEAD.json`: decode two
// evaluate Responses (the JSON the default subcommand emits — typically one per
// git checkout) and report the flows that changed between them. Default output
// is human-readable text; -format markdown emits the PR-comment table and
// -format json the structured DiffReport. -exit-code makes the command exit 1
// when anything changed, so a pipeline can choose to gate on drift.
func runDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text | markdown | json")
	exitCode := fs.Bool("exit-code", false, "exit non-zero when any flow changed (git diff --exit-code style)")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 2 {
		fail("diff: need exactly two Response files: diff [flags] BASE.json HEAD.json")
	}
	base := loadResponseFile(rest[0])
	head := loadResponseFile(rest[1])

	report := api.DiffResponses(base, head)

	switch *format {
	case "text":
		fmt.Print(formatDiffText(report))
	case "markdown", "md":
		fmt.Print(api.FormatDiffMarkdown(report))
	case "json":
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			fail("encode report: %v", err)
		}
	default:
		fail("unknown -format %q (want text|markdown|json)", *format)
	}

	if *exitCode && report.Changed() {
		os.Exit(1)
	}
}

// loadResponseFile reads and decodes one evaluate Response (JSON or YAML) from
// a file, failing with a precise message — the two diff operands are the most
// common thing to mistype.
func loadResponseFile(path string) api.Response {
	data, err := os.ReadFile(path)
	if err != nil {
		fail("read response %s: %v", path, err)
	}
	resp, err := api.DecodeResponse(data)
	if err != nil {
		fail("decode response %s: %v", path, err)
	}
	return resp
}

// formatDiffText renders the diff as a grep-friendly list: one line per changed
// flow (kind, flow, before->after) plus a summary, or a single "no changes"
// line. Mirrors the text the markdown table carries, for terminal/CI logs.
func formatDiffText(r api.DiffReport) string {
	var b strings.Builder
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "# ERROR: %s\n", e)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "# WARNING: %s\n", w)
	}
	if !r.Changed() {
		b.WriteString("no connectivity changes\n")
		return b.String()
	}
	for _, c := range r.Changes {
		base, head := c.Base, c.Head
		if base == "" {
			base = "-"
		}
		if head == "" {
			head = "-"
		}
		fmt.Fprintf(&b, "%-8s %s -> %s  (%s -> %s)\n", c.Kind, c.From, c.To, base, head)
	}
	fmt.Fprintf(&b, "\n%d changed: %d opened, %d closed, %d added, %d removed (%d unchanged)\n",
		len(r.Changes), r.Opened, r.Closed, r.Added, r.Removed, r.Unchanged)
	return b.String()
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}
