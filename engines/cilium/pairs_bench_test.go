// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"github.com/frozenprocess/telepathy/api"
	"testing"
)

// Includes graph/repository construction, not just the pair loop.
func BenchmarkMatrixSelection(b *testing.B) {
	for _, n := range []int{100, 500} {
		for _, selected := range []bool{false, true} {
			b.Run(fmt.Sprintf("endpoints=%d/selected=%t", n, selected), func(b *testing.B) {
				req := api.Request{Namespaces: []api.NamespaceInput{{Name: "bench"}}, Port: 8080, Protocol: "tcp"}
				for i := 0; i < n; i++ {
					name := fmt.Sprintf("pod-%d", i)
					req.Endpoints = append(req.Endpoints, api.Endpoint{ID: "bench/" + name, Name: name, Namespace: "bench", IP: fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), Labels: map[string]string{"app": "bench"}})
				}
				req.Policies = []api.PolicyInput{{Flavor: "k8s", YAML: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-bench, namespace: bench}
spec:
  podSelector: {matchLabels: {app: bench}}
  policyTypes: [Ingress]
  ingress:
  - from: [{podSelector: {matchLabels: {app: bench}}}]
    ports: [{protocol: TCP, port: 8080}]
`}}
				if selected {
					for i := 0; i < 10; i++ {
						req.MatrixPairs = append(req.MatrixPairs, api.MatrixPair{From: req.Endpoints[i].ID, To: req.Endpoints[n-1].ID})
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					resp := evaluate(req)
					if len(resp.Errors) > 0 {
						b.Fatal(resp.Errors)
					}
					want := n * (n - 1)
					if selected {
						want = 10
					}
					if len(resp.Matrix) != want {
						b.Fatalf("pairs=%d want=%d", len(resp.Matrix), want)
					}
				}
			})
		}
	}
}
