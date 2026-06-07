package engine

import (
	"fmt"
	"regexp"
	"strings"

	"sigs.k8s.io/yaml"
)

// docSep splits a multi-document YAML stream on lines that are exactly `---`
// (the standard document separator). Leading/trailing/doubled separators yield
// empty chunks, which ParsePolicyManifests drops.
var docSep = regexp.MustCompile(`(?m)^---\s*$`)

// DecodeRequest parses a Request from raw bytes that may be either JSON or
// YAML. sigs.k8s.io/yaml converts YAML to JSON first, so the struct's json
// tags drive both formats and a JSON Request decodes exactly as it did before.
// Empty input yields a zero Request (no error), letting a caller supply the
// whole topology via -policy files instead of stdin.
func DecodeRequest(data []byte) (Request, error) {
	var req Request
	if strings.TrimSpace(string(data)) == "" {
		return req, nil
	}
	if err := yaml.Unmarshal(data, &req); err != nil {
		return req, fmt.Errorf("decode request: %w", err)
	}
	return req, nil
}

// ParsePolicyManifests turns the raw contents of a policy file (one or more
// `---`-separated YAML documents) into PolicyInputs. Each document's flavor is
// auto-detected from its apiVersion — only the ambiguous kind: NetworkPolicy
// needs it. Blank / comment-only documents are skipped; a malformed document
// is kept (with the best-effort flavor) so the evaluator reports its error in
// Response.Errors, matching how an inline PolicyInput already behaves.
func ParsePolicyManifests(data []byte) []PolicyInput {
	var out []PolicyInput
	for _, doc := range docSep.Split(string(data), -1) {
		if isBlankDoc(doc) {
			continue
		}
		out = append(out, PolicyInput{Flavor: detectFlavor([]byte(doc)), YAML: doc})
	}
	return out
}

// detectFlavor returns "k8s" for a networking.k8s.io NetworkPolicy and ""
// otherwise. feedPolicy treats the empty flavor as the Calico path, so every
// non-k8s kind (Calico NetworkPolicy, GlobalNetworkPolicy, Tier, NetworkSet, …)
// is handled without an explicit flavor. A document that doesn't parse here
// yields "" and is left for feedPolicy to reject with a precise message.
func detectFlavor(doc []byte) string {
	var tm struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	if err := yaml.Unmarshal(doc, &tm); err != nil {
		return ""
	}
	if tm.Kind == "NetworkPolicy" && strings.HasPrefix(tm.APIVersion, "networking.k8s.io/") {
		return "k8s"
	}
	return ""
}

// isBlankDoc reports whether a YAML document carries no content — only blank
// lines and # comments. Such chunks come from leading/trailing/doubled `---`
// separators and would otherwise become spurious empty policies.
func isBlankDoc(doc string) bool {
	for _, line := range strings.Split(doc, "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "#") {
			return false
		}
	}
	return true
}
