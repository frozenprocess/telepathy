// SPDX-License-Identifier: Apache-2.0
package api

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEndpointPairs(t *testing.T) {
	endpoints := []Endpoint{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	pairs := []MatrixPair{{From: "a", To: "b"}, {From: "a", To: "b"}, {From: "b", To: "a"}, {From: "a", To: "a"}, {From: "missing", To: "a"}}
	var got [][2]int
	for i, j := range EndpointPairs(endpoints, pairs) {
		got = append(got, [2]int{i, j})
	}
	if !reflect.DeepEqual(got, [][2]int{{0, 1}, {1, 0}}) {
		t.Fatal(got)
	}
	count := 0
	for range EndpointPairs(endpoints, nil) {
		count++
	}
	if count != 6 {
		t.Fatal(count)
	}
	count = 0
	for range EndpointPairs(endpoints, pairs) {
		count++
		break
	}
	if count != 1 {
		t.Fatal(count)
	}
}

func TestAssertionsRequestOnlyTheirProbePairs(t *testing.T) {
	req := Request{Endpoints: []Endpoint{{ID: "a"}, {ID: "b"}, {ID: "c"}}, MatrixPairs: []MatrixPair{{From: "unrelated", To: "pair"}}}
	assertions := []Assertion{{From: "a", To: "b", Expect: "allow", Port: 80}, {From: "b", To: "c", Expect: "deny", Port: 443}}
	calls := 0
	report := RunAssertions(func(probe Request) Response {
		calls++
		if len(probe.Endpoints) != 3 || len(probe.MatrixPairs) != 1 {
			t.Fatalf("unexpected probe: %+v", probe)
		}
		// Verify the selection survives the subprocess JSON contract.
		data, err := json.Marshal(probe)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Request
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded.MatrixPairs, probe.MatrixPairs) {
			t.Fatal("selection lost")
		}
		pair := probe.MatrixPairs[0]
		verdict := "allow"
		if probe.Port == 443 {
			verdict = "deny"
		}
		return Response{Matrix: map[string]string{pair.From + "->" + pair.To: verdict}}
	}, req, assertions)
	if !report.Ok() || calls != 2 || req.MatrixPairs[0].From != "unrelated" {
		t.Fatalf("report=%+v calls=%d", report, calls)
	}
}
