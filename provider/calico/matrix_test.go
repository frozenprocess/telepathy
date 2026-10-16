// SPDX-License-Identifier: Apache-2.0
package calico

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

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
