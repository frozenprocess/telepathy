// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"fmt"
	"github.com/frozenprocess/telepathy/api"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaultShortcutsMatchNative(t *testing.T) {
	files, err := filepath.Glob("../../e2e/testdata/*/meta.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, meta := range files {
		data, err := os.ReadFile(meta)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte("flavor: k8s")) && !bytes.Contains(data, []byte("flavor: antrea")) {
			continue
		}
		dir := filepath.Dir(meta)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			read := func(name string) []byte {
				b, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			req, err := api.DecodeRequest(read("topology.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			req.Policies = append(req.Policies, api.ParsePolicyManifests(read("policy.yaml"))...)
			assertions, err := api.DecodeAssertions(read("assertions.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			api.RunAssertions(func(probe api.Request) api.Response {
				probe.MatrixPairs = nil
				native := evaluateWithDefaults(probe, false)
				fast := evaluateWithDefaults(probe, true)
				if !reflect.DeepEqual(fast, native) {
					t.Fatalf("optimized response differs\nfast=%+v\nnative=%+v", fast, native)
				}
				return fast
			}, req, assertions)
		})
	}
}

func defaultBenchmarkRequest(n, policies int) api.Request {
	req := api.Request{Namespaces: []api.NamespaceInput{{Name: "bench"}}, Port: 8080, Protocol: "tcp"}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("pod-%d", i)
		group := "other"
		if i < n/10 {
			group = "selected"
		}
		req.Endpoints = append(req.Endpoints, api.Endpoint{ID: "bench/" + name, Name: name, Namespace: "bench", IP: fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), Labels: map[string]string{"group": group}})
	}
	for i := 0; i < policies; i++ {
		req.Policies = append(req.Policies, api.PolicyInput{Flavor: "k8s", YAML: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: policy-%d, namespace: bench}
spec:
  podSelector: {matchLabels: {group: selected}}
  policyTypes: [Ingress]
  ingress:
  - ports: [{protocol: TCP, port: 9090}]
`, i)})
	}
	return req
}

func TestUnrestrictedThousandEndpoints(t *testing.T) {
	resp := evaluate(defaultBenchmarkRequest(1000, 0))
	if len(resp.Errors) > 0 || len(resp.Matrix) != 999000 {
		t.Fatalf("errors=%v pairs=%d", resp.Errors, len(resp.Matrix))
	}
	for pair, verdict := range resp.Matrix {
		if verdict != "allow" {
			t.Fatalf("%s: %s", pair, verdict)
		}
	}
}

func BenchmarkDefaultShortcuts(b *testing.B) {
	for _, policies := range []int{0, 100} {
		for _, optimize := range []bool{false, true} {
			b.Run(fmt.Sprintf("policies=%d/optimized=%t", policies, optimize), func(b *testing.B) {
				req := defaultBenchmarkRequest(100, policies)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					resp := evaluateWithDefaults(req, optimize)
					if len(resp.Errors) > 0 {
						b.Fatal(resp.Errors)
					}
				}
			})
		}
	}
}

func TestSelectedEndpointsWithNoMatchingRules(t *testing.T) {
	req := defaultBenchmarkRequest(20, 100)
	resp := evaluate(req)
	native := evaluateWithDefaults(req, false)
	if !reflect.DeepEqual(resp, native) {
		t.Fatal("default shortcut changed native results")
	}
	for i, src := range req.Endpoints {
		for j, dst := range req.Endpoints {
			if i == j {
				continue
			}
			want := "allow"
			if j < 2 {
				want = "deny"
			} // selected for ingress, but port 8080 misses every rule
			if got := resp.Matrix[src.ID+"->"+dst.ID]; got != want {
				t.Fatalf("%s -> %s: %s, want %s", src.ID, dst.ID, got, want)
			}
		}
	}
}
