// SPDX-License-Identifier: Apache-2.0
package calico

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/frozenprocess/telepathy/api"
)

// Compare complete responses so service columns, internet posture, and HEP
// overlays are covered along with ordinary workload verdicts.
func TestMatrixModesAgree(t *testing.T) {
	dirs, err := filepath.Glob("../../e2e/testdata/*/meta.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, meta := range dirs {
		data, err := os.ReadFile(meta)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte("flavor: calico")) && !bytes.Contains(data, []byte("flavor: k8s")) {
			continue
		}
		dir := filepath.Dir(meta)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			read := func(name string) []byte {
				t.Helper()
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
			compare := func(req Request) Response {
				t.Setenv("TELEPATHY_NO_COLLAPSE", "1")
				want := Evaluate(req)
				t.Setenv("TELEPATHY_NO_COLLAPSE", "")
				got := Evaluate(req)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("collapsed differs from exact\ngot: %+v\nwant: %+v", got, want)
				}
				for _, disable := range []string{"", "1"} {
					t.Setenv("TELEPATHY_NO_COLLAPSE", disable)
					var buf bytes.Buffer
					req.MatrixSink = &buf
					streamed := Evaluate(req)
					if streamed.Matrix != nil {
						t.Fatal("streaming returned a resident matrix")
					}
					streamed.Matrix = map[string]string{}
					for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
						if line == "" {
							continue
						}
						key, value, ok := strings.Cut(line, "\t")
						if !ok {
							t.Fatalf("invalid matrix line %q", line)
						}
						streamed.Matrix[key] = value
					}
					if want.Matrix == nil && len(streamed.Matrix) == 0 {
						streamed.Matrix = nil
					}
					if !reflect.DeepEqual(streamed, want) {
						t.Fatalf("streaming differs from exact\ngot: %+v\nwant: %+v", streamed, want)
					}
				}
				return want
			}
			// Exercise every port/protocol in each fixture, plus staged promotion.
			api.RunAssertions(compare, req, assertions)
			req.EvaluateStaged = true
			compare(req)
		})
	}
}

type brokenMatrixWriter struct{}

func (brokenMatrixWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestMatrixSinkRetentionAndErrors(t *testing.T) {
	var buf bytes.Buffer
	sink := newMatrixSink(&buf, map[string]bool{"backend": true})
	sink.put("src", "backend", "allow")
	sink.put("src", "other", "deny")
	if len(sink.m) != 1 || sink.get("src", "backend") != "allow" {
		t.Fatalf("retained matrix: %v", sink.m)
	}
	if err := sink.flush(); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "src->backend\tallow\nsrc->other\tdeny\n" {
		t.Fatalf("stream: %q", buf.String())
	}
	req := assertTopology()
	req.MatrixSink = brokenMatrixWriter{}
	resp := Evaluate(req)
	if len(resp.Errors) == 0 || !strings.Contains(strings.Join(resp.Errors, " "), "disk full") {
		t.Fatalf("missing write error: %+v", resp)
	}
}
