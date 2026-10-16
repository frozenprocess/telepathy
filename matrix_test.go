// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/frozenprocess/telepathy/api"
)

type failingMatrixWriter struct{}

func (failingMatrixWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestMatrixFileAssertions(t *testing.T) {
	matrix := map[string]string{"a->b": "allow", "b->a": "deny", "unused->pair": "allow"}
	var buf bytes.Buffer
	if err := writeMatrixTSV(&buf, matrix); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "matrix.tsv")
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	assertions := []api.Assertion{
		{From: "a", To: "b", Expect: "allow", Port: 9090, Protocol: "udp"},
		{From: "b", To: "a", Expect: "deny"},
		{From: "missing", To: "b", Expect: "deny"},
		{From: "a", To: "b", Expect: "invalid"},
		{To: "b", Expect: "allow"},
	}
	report, err := runAssertionsFromMatrixFile(path, assertions)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed != 2 || report.Failed != 3 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if _, err := runAssertionsFromMatrixFile(path+".missing", assertions); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := writeMatrixTSV(failingMatrixWriter{}, matrix); err == nil {
		t.Fatal("writer error lost")
	}
}
