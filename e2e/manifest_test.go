// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Telepathy Authors

//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"github.com/frozenprocess/telepathy/api"
	"sigs.k8s.io/yaml"
)

// parseYAML unmarshals a rendered manifest into a generic map, failing the test if
// it isn't valid YAML — the first thing a builder regression would break.
func parseYAML(t *testing.T, label, doc string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("%s: not valid YAML: %v\n---\n%s", label, err, doc)
	}
	return m
}

func TestManifestPod(t *testing.T) {
	ep := api.Endpoint{
		ID: "ns1/frontend", Name: "frontend", Namespace: "ns1",
		Labels:             map[string]string{"app": "frontend", "kubernetes.io/metadata.name": "ns1"},
		ServiceAccountName: "fe-sa",
		Node:               "worker-1",
	}
	doc := podManifest(ep, serverPlan{tcp: []int{8080}, udp: []int{8081}, sctp: []int{9000}}, map[string]bool{"worker-1": true}, "agn:1", "ns:1")
	m := parseYAML(t, "pod", doc)
	if m["apiVersion"] != "v1" || m["kind"] != "Pod" {
		t.Fatalf("pod apiVersion/kind wrong: %v", m)
	}
	meta := m["metadata"].(map[string]any)
	if meta["name"] != "frontend" || meta["namespace"] != "ns1" {
		t.Fatalf("pod metadata wrong: %v", meta)
	}
	labels := meta["labels"].(map[string]any)
	if labels["kubernetes.io/metadata.name"] != "ns1" {
		t.Fatalf("dotted/slashed label not preserved: %v", labels)
	}
	spec := m["spec"].(map[string]any)
	if spec["nodeName"] != "worker-1" || spec["serviceAccountName"] != "fe-sa" {
		t.Fatalf("pod spec wrong: %v", spec)
	}
	conts := spec["containers"].([]any)
	if len(conts) != 2 {
		t.Fatalf("want 2 containers, got %d", len(conts))
	}
	agn := conts[0].(map[string]any)
	cmd := agn["command"].([]any)
	// agnhost command must carry the SCTP flag when sctpPort != 0.
	joined := ""
	for _, c := range cmd {
		joined += c.(string) + " "
	}
	for _, want := range []string{"--http-port=8080", "--udp-port=8081", "--sctp-port=9000"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("agnhost command missing %q: %v", want, cmd)
		}
	}
}

// A case probing one protocol on several ports must serve a listener on each:
// a single netexec binds only one TCP port, so the rendered command launches one
// netexec per TCP port under a shell. Without this, the second port has no
// listener and probes to it are REFUSED.
func TestManifestPodMultipleTCPPorts(t *testing.T) {
	ep := api.Endpoint{Name: "p", Namespace: "n", Labels: map[string]string{"a": "b"}}
	doc := podManifest(ep, serverPlan{tcp: []int{8080, 9090}, udp: []int{8081}}, nil, "agn", "ns")
	m := parseYAML(t, "pod", doc)
	cmd := m["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["command"].([]any)
	joined := ""
	for _, c := range cmd {
		joined += c.(string) + " "
	}
	// Both TCP ports get a netexec --http-port; multiple listeners run under sh -c.
	for _, want := range []string{"sh", "--http-port=8080", "--http-port=9090"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("multi-port command missing %q: %v", want, cmd)
		}
	}
}

func TestManifestPodOmitsNodeNameForUnknownNode(t *testing.T) {
	ep := api.Endpoint{Name: "p", Namespace: "n", Node: "ghost", Labels: map[string]string{"a": "b"}}
	doc := podManifest(ep, serverPlan{tcp: []int{8080}, udp: []int{8081}}, map[string]bool{"worker-1": true}, "agn", "ns")
	if strings.Contains(doc, "nodeName") {
		t.Fatalf("nodeName must be omitted for a node not in the cluster:\n%s", doc)
	}
	if strings.Contains(doc, "sctp-port") {
		t.Fatalf("sctp flag must be absent when sctpPort==0:\n%s", doc)
	}
}

func TestManifestServiceTargetPortIntOrString(t *testing.T) {
	// Numeric targetPort must be unquoted (an int); a named one must be quoted.
	numeric := serviceManifest(api.ServiceInput{
		Name: "svc", Namespace: "n", Type: "NodePort",
		Selector: map[string]string{"app": "x"},
		Ports:    []api.ServicePort{{Port: 80, TargetPort: "8080", NodePort: 30080}},
	})
	if !strings.Contains(numeric, "targetPort: 8080\n") {
		t.Fatalf("numeric targetPort must be unquoted:\n%s", numeric)
	}
	if !strings.Contains(numeric, "nodePort: 30080\n") {
		t.Fatalf("nodePort missing/wrong:\n%s", numeric)
	}
	named := serviceManifest(api.ServiceInput{
		Name: "svc", Namespace: "n",
		Ports: []api.ServicePort{{Port: 80, TargetPort: "http"}},
	})
	if !strings.Contains(named, `targetPort: "http"`) {
		t.Fatalf("named targetPort must be quoted:\n%s", named)
	}
	// Both must round-trip as valid YAML.
	parseYAML(t, "svc-numeric", numeric)
	parseYAML(t, "svc-named", named)
}

func TestManifestNetworkSetsAndHEP(t *testing.T) {
	ns := networkSetManifest(api.NetworkSetInput{
		Name: "set", Namespace: "n",
		Labels: map[string]string{"role": "db"},
		Nets:   []string{"10.0.0.1/32", "10.0.0.2/32"},
	})
	m := parseYAML(t, "networkset", ns)
	if m["kind"] != "NetworkSet" {
		t.Fatalf("kind wrong: %v", m)
	}
	nets := m["spec"].(map[string]any)["nets"].([]any)
	if len(nets) != 2 || nets[0] != "10.0.0.1/32" {
		t.Fatalf("nets wrong: %v", nets)
	}

	gns := globalNetworkSetManifest(api.GlobalNetworkSetInput{Name: "g", Nets: []string{"1.2.3.4/32"}})
	if gm := parseYAML(t, "gns", gns); gm["kind"] != "GlobalNetworkSet" {
		t.Fatalf("gns kind wrong: %v", gm)
	}

	hep := hostEndpointManifest(api.HostEndpointInput{
		Name: "hep", Node: "worker-1",
		Labels:      map[string]string{"endpoint": "host"},
		ExpectedIPs: []string{"172.18.0.3"},
	})
	hm := parseYAML(t, "hep", hep)
	hspec := hm["spec"].(map[string]any)
	if hspec["interfaceName"] != "*" {
		t.Fatalf("HEP interfaceName default must be '*': %v", hspec)
	}
	if ips := hspec["expectedIPs"].([]any); len(ips) != 1 || ips[0] != "172.18.0.3" {
		t.Fatalf("HEP expectedIPs wrong: %v", hspec["expectedIPs"])
	}
}

func TestManifestServiceAccountOmitsEmptyLabels(t *testing.T) {
	doc := serviceAccountManifest(api.ServiceAccountInput{Name: "sa", Namespace: "n"})
	if strings.Contains(doc, "labels:") {
		t.Fatalf("empty labels block should be omitted:\n%s", doc)
	}
	parseYAML(t, "sa", doc)
}
