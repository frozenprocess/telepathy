package engine

import "testing"

// inlineCommonInputs is the shared topology for the paste tests: two pods in
// namespace "ns", a (with ServiceAccount "frontend") and b. Tests layer a
// policy plus a pasted ServiceAccount/Service on top and check that the pasted
// resource resolves exactly as the typed Request field would.
func inlineCommonInputs() Request {
	return Request{
		Namespaces: []NamespaceInput{{Name: "ns", Labels: map[string]string{"name": "ns"}}},
		Endpoints: []Endpoint{
			{ID: "ns/a", Namespace: "ns", Name: "a", IP: "10.0.0.1",
				Labels: map[string]string{"app": "a"}, ServiceAccountName: "frontend"},
			{ID: "ns/b", Namespace: "ns", Name: "b", IP: "10.0.0.2",
				Labels: map[string]string{"app": "b"}},
		},
		Port:     8080,
		Protocol: "tcp",
	}
}

const saPolicy = `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: allow-from-frontend-sa}
spec:
  selector: app == "b"
  types: [Ingress]
  ingress:
  - action: Allow
    source:
      serviceAccounts:
        selector: team == "payments"
`

const saYAML = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: frontend
  namespace: ns
  labels:
    team: payments
`

// TestServiceAccountPasteMatchesTypedInput: a ServiceAccount pasted into the
// policy list must project its labels onto the matching endpoint exactly as
// Request.ServiceAccounts does, so a serviceAccounts.selector rule resolves
// either way. The verdict is allow only if the SA actually resolved — if the
// paste path dropped it (the pre-fix "unsupported policy kind" behaviour) a→b
// would deny — so this is non-vacuous.
func TestServiceAccountPasteMatchesTypedInput(t *testing.T) {
	typed := inlineCommonInputs()
	typed.Policies = []PolicyInput{{YAML: saPolicy}}
	typed.ServiceAccounts = []ServiceAccountInput{
		{Name: "frontend", Namespace: "ns", Labels: map[string]string{"team": "payments"}},
	}

	pasted := inlineCommonInputs()
	pasted.Policies = []PolicyInput{{YAML: saPolicy}, {YAML: saYAML}}

	assertSameMatrix(t, typed, pasted)
}

const svcPolicy = `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: {name: allow-to-web-svc}
spec:
  selector: app == "a"
  types: [Egress]
  egress:
  - action: Allow
    destination:
      services:
        name: web
        namespace: ns
`

const svcYAML = `
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: ns
spec:
  selector:
    app: b
  ports:
  - name: http
    port: 8080
    protocol: TCP
    targetPort: 8080
`

// TestServicePasteMatchesTypedInput: a Service pasted into the policy list must
// resolve a destination.services rule the same way Request.Services does — the
// engine auto-derives an EndpointSlice from the matching workload either way.
// If the paste path dropped the Service, the egress rule would resolve to an
// empty IP set and a→b would deny.
func TestServicePasteMatchesTypedInput(t *testing.T) {
	typed := inlineCommonInputs()
	typed.Policies = []PolicyInput{{YAML: svcPolicy}}
	typed.Services = []ServiceInput{
		{Name: "web", Namespace: "ns", Selector: map[string]string{"app": "b"},
			Ports: []ServicePort{{Name: "http", Port: 8080, Protocol: "tcp"}}},
	}

	pasted := inlineCommonInputs()
	pasted.Policies = []PolicyInput{{YAML: svcPolicy}, {YAML: svcYAML}}

	assertSameMatrix(t, typed, pasted)
}

// assertSameMatrix evaluates both requests, fails on any parse error, asserts
// the pasted path produced the same matrix as the typed path, and asserts a→b
// allows (so an equal-but-all-deny matrix can't pass vacuously).
func assertSameMatrix(t *testing.T, typed, pasted Request) {
	t.Helper()
	typedResp := Evaluate(typed)
	pastedResp := Evaluate(pasted)
	for _, e := range typedResp.Errors {
		t.Fatalf("typed input error: %s", e)
	}
	for _, e := range pastedResp.Errors {
		t.Fatalf("pasted input error: %s", e)
	}
	mustVerdict(t, typedResp, "ns/a->ns/b", "allow")
	mustVerdict(t, pastedResp, "ns/a->ns/b", "allow")
	for pair, want := range typedResp.Matrix {
		if got := pastedResp.Matrix[pair]; got != want {
			t.Errorf("%s: pasted %q != typed %q", pair, got, want)
		}
	}
	if len(pastedResp.Matrix) != len(typedResp.Matrix) {
		t.Errorf("matrix size differs: pasted %d vs typed %d",
			len(pastedResp.Matrix), len(typedResp.Matrix))
	}
}
