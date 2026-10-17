// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Telepathy Authors

//go:build e2e

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Simulate an unavailable aggregated API while the Kubernetes datastore still
// answers. Recovery must remove the HEP before attempting any Calico API calls.
func TestRepairHEPWithoutCalicoAPIServer(t *testing.T) {
	for _, group := range []string{"crd.projectcalico.org", "projectcalico.org"} {
		t.Run(group, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			script := `#!/bin/sh
printf '%s\n' "$*" >> "$HEP_TEST_LOG"
shift 2
case "$1 $2" in
  'get customresourcedefinitions.apiextensions.k8s.io') printf 'hostendpoints.STORAGE_GROUP';;
  'get hostendpoints.STORAGE_GROUP') printf 'fw-worker fw-worker2';;
  'delete hostendpoints.STORAGE_GROUP') exit 0;;
  'delete ippools.STORAGE_GROUP') exit 0;;
  'get nodes') printf '' ;;
  *) echo 'aggregated API unavailable' >&2; exit 1;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(strings.ReplaceAll(script, "STORAGE_GROUP", group)), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("HEP_TEST_LOG", log)
			old := cfg
			t.Cleanup(func() { cfg = old })
			cfg.Provider = "calico"
			cfg.HEPSettleDelay = 0
			c := &cluster{ctx: "test"}
			repairLeakedHEPState(context.Background(), t, c)
			data, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			calls := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(calls) != 6 || !strings.Contains(calls[3], "delete hostendpoints."+group+" fw-worker fw-worker2 --ignore-not-found --wait=true") || !strings.Contains(calls[4], "delete ippools."+group+" telepathy-node-subnet") {
				t.Fatalf("unexpected recovery sequence:\n%s", data)
			}
		})
	}
}

func TestDeleteHostEndpointsReportsFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(`#!/bin/sh
shift 2
if [ "$1" = get ]; then echo hostendpoints.projectcalico.org; exit 0; fi
echo 'datastore unavailable' >&2
exit 1
`), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	c := &cluster{ctx: "test"}
	if err := c.deleteHostEndpoints(context.Background(), nil); err != nil {
		t.Fatalf("empty cleanup: %v", err)
	}
	err := c.deleteHostEndpoints(context.Background(), []string{"fw-worker"})
	if err == nil || !strings.Contains(err.Error(), "datastore unavailable") {
		t.Fatalf("expected datastore error, got %v", err)
	}
}

func TestRestartCalicoControlPlaneLayouts(t *testing.T) {
	for _, layout := range []struct{ name, namespace string }{
		{"calico-webhooks", "calico-system"},
		{"calico-apiserver", "calico-apiserver"},
	} {
		t.Run(layout.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			script := `#!/bin/sh
printf '%s\n' "$*" >> "$HEP_TEST_LOG"
shift 2
if [ "$1 $2" = 'get deployments.apps' ]; then
  printf '%s' '{"items":[{"metadata":{"name":"CONTROL_NAME","namespace":"CONTROL_NS"}},{"metadata":{"name":"calico-kube-controllers","namespace":"calico-system"}},{"metadata":{"name":"calico-webhooks","namespace":"unrelated"}}]}'
  exit 0
fi
case "$*" in
 '-n CONTROL_NS rollout restart deployment/CONTROL_NAME'|'-n CONTROL_NS rollout status deployment/CONTROL_NAME --timeout=1s'|'-n calico-system rollout restart deployment/calico-kube-controllers'|'-n calico-system rollout status deployment/calico-kube-controllers --timeout=1s') exit 0;;
 *) echo 'unexpected deployment' >&2; exit 1;;
esac
`
			script = strings.NewReplacer("CONTROL_NAME", layout.name, "CONTROL_NS", layout.namespace).Replace(script)
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("HEP_TEST_LOG", log)
			c := &cluster{ctx: "test"}
			if _, err := c.restartCalicoControlPlane(context.Background(), time.Second); err != nil {
				t.Fatal(err)
			}
			calls, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if len(strings.Split(strings.TrimSpace(string(calls)), "\n")) != 5 {
				t.Fatalf("missing rollout: %s", calls)
			}
		})
	}
}
