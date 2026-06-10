// Command calico-engine is an in-process evaluator for Kubernetes/Calico
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
//	calico-engine            evaluate connectivity (default; Request in,
//	                         JSON Response out — the harness contract).
//	calico-engine iptables   render the iptables/nftables chains Felix would
//	                         program for the same Request. Text output by
//	                         default; -json for the structured form.
//	calico-engine bpf        render the eBPF policy program Felix would
//	                         JIT-assemble per endpoint+direction for the same
//	                         Request (annotated disassembly).
//	calico-engine version    print the engine version, the pinned Calico
//	                         version it is built against, and its capabilities
//	                         (also reachable as --version / -version).
//
// All semantics live in the importable ./engine subpackage; this binary is
// a CLI shim around engine.Evaluate / engine.RenderIptables so callers like
// the policy_llm harness keep working unchanged. Servers that want to avoid
// per-request fork/exec can import ./engine directly (see ../editor/).
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

	"github.com/frozenprocess/telepathy/engine"
)

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
	// engineVersion is the calico-engine binary's own version.
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
	{"iptables", "render the iptables/nftables chains Felix would program"},
	{"bpf", "render the eBPF policy program Felix would JIT-assemble per endpoint/direction"},
	{"hns", "render the Windows HNS ACL rules Felix would program per endpoint/direction"},
}

// printVersion writes the version banner and capability list to stdout. It is
// reached by the top-level `version` subcommand and the `--version`/`-version`
// flags.
func printVersion() {
	fmt.Printf("calico-engine %s\n", engineVersion)
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

	fs := flag.NewFlagSet("calico-engine", flag.ExitOnError)
	policies := addRequestFlags(fs)
	_ = fs.Parse(os.Args[1:])

	req := loadRequest(*policies)
	resp := engine.Evaluate(req)
	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		fail("encode response: %v", err)
	}
}

// stringSlice collects a repeatable flag (e.g. -policy a.yaml -policy b.yaml).
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// addRequestFlags registers the input flags shared by every subcommand and
// returns the slice the -policy values land in.
func addRequestFlags(fs *flag.FlagSet) *stringSlice {
	var policies stringSlice
	fs.Var(&policies, "policy", "raw policy manifest YAML file or directory to append to the stdin Request (repeatable)")
	return &policies
}

// loadRequest builds the Request: decode stdin (JSON or YAML, when piped), then
// append every policy parsed from the -policy files/directories. Stdin and
// -policy compose — stdin carries the topology, -policy adds manifests — but
// either may be omitted.
func loadRequest(policyPaths []string) engine.Request {
	data, err := readPipedStdin()
	if err != nil {
		fail("read stdin: %v", err)
	}
	req, err := engine.DecodeRequest(data)
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
			req.Policies = append(req.Policies, engine.ParsePolicyManifests(b)...)
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

// runIptables implements `calico-engine iptables`: read the same JSON Request
// from stdin, render the dataplane chains, print them.
func runIptables(args []string) {
	fs := flag.NewFlagSet("iptables", flag.ExitOnError)
	backend := fs.String("backend", "iptables", "dataplane to render: iptables | nftables | both")
	ipv := fs.String("ipversion", "", "IP version(s) to render: 4 | 6 | both (default: inferred from endpoints)")
	noStatic := fs.Bool("no-static", false, "omit Felix's static top-level chains (cali-INPUT/FORWARD/OUTPUT); show only policy/endpoint/profile chains")
	asJSON := fs.Bool("json", false, "emit the structured JSON response instead of text")
	policies := addRequestFlags(fs)
	_ = fs.Parse(args)

	req := loadRequest(*policies)

	opts := engine.IptablesOptions{IncludeStatic: !*noStatic}
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

	resp := engine.RenderIptables(req, opts)

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
func formatIptables(resp engine.IptablesResponse) string {
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

// runBPF implements `calico-engine bpf`: read the same JSON Request from
// stdin, render each endpoint's eBPF policy program, print the annotated
// disassembly. Renders all endpoints + both directions by default; -endpoint
// and -direction narrow that.
func runBPF(args []string) {
	fs := flag.NewFlagSet("bpf", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "only render endpoints whose ID contains this substring (default: all)")
	dir := fs.String("direction", "both", "direction(s) to render: ingress | egress | both")
	ipv := fs.String("ipversion", "", "IP version(s) to render: 4 | 6 | both (default: inferred from endpoints)")
	asJSON := fs.Bool("json", false, "emit the structured JSON response instead of text")
	policies := addRequestFlags(fs)
	_ = fs.Parse(args)

	req := loadRequest(*policies)

	var opts engine.BPFOptions
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

	resp := engine.RenderBPF(req, opts)

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
func formatBPF(resp engine.BPFResponse) string {
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

// runHNS implements `calico-engine hns`: read the same JSON Request from
// stdin, render each endpoint's Windows HNS ACL list, print it. Renders all
// endpoints + both directions by default; -endpoint and -direction narrow that.
// HNS is IPv4-only, so there is no -ipversion flag.
func runHNS(args []string) {
	fs := flag.NewFlagSet("hns", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "only render endpoints whose ID contains this substring (default: all)")
	dir := fs.String("direction", "both", "direction(s) to render: ingress | egress | both")
	asJSON := fs.Bool("json", false, "emit the structured JSON response instead of text")
	policies := addRequestFlags(fs)
	_ = fs.Parse(args)

	req := loadRequest(*policies)

	var opts engine.HNSOptions
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

	resp := engine.RenderHNS(req, opts)

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
func formatHNS(resp engine.HNSResponse) string {
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
func formatHNSRule(r engine.HNSRule) string {
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

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}
