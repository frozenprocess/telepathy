#!/usr/bin/env bash
# Create a local kind cluster with Antrea installed (idempotent).
#
# Antrea enforces upstream Kubernetes NetworkPolicy, which is what the
# out-of-process Antrea engine (engines/antrea) predicts. The e2e harness then
# compares the engine's prediction against this cluster's real connectivity for
# every k8s-flavored e2e/testdata case (see `make e2e-antrea`).
#
# This is a SEPARATE cluster from the Calico e2e one (a node can run only one
# CNI), hence the distinct default CLUSTER_NAME.
#
# Env overrides:
#   CLUSTER_NAME    (default: telepathy-e2e-calico-antrea)
#   ANTREA_VERSION  (default: v2.6.1) — kept in step with the engine's pinned
#                    Antrea source tree (Makefile ANTREA_VERSION) so the
#                    dataplane and the engine implement the same semantics.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-telepathy-e2e-calico-antrea}"
ANTREA_VERSION="${ANTREA_VERSION:-v2.6.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANTREA_URL="https://github.com/antrea-io/antrea/releases/download/${ANTREA_VERSION}/antrea.yml"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  log "kind cluster '$CLUSTER_NAME' already exists — reusing"
else
  log "Creating kind cluster '$CLUSTER_NAME' (default CNI disabled)"
  kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/antrea-kind.yaml"
fi

kubectl config use-context "kind-$CLUSTER_NAME" >/dev/null

log "Installing Antrea ($ANTREA_VERSION)"
# Server-side apply keeps this idempotent across re-runs (the manifest carries
# large CRDs whose client-side last-applied annotation would overflow).
kubectl apply --server-side --force-conflicts -f "$ANTREA_URL"

log "Waiting for antrea-controller + antrea-agent"
# The controller Deployment and the per-node agent DaemonSet both live in
# kube-system. The agent installs the CNI plugin on each node, so nodes only go
# Ready once it has rolled out.
kubectl -n kube-system rollout status deploy/antrea-controller --timeout=300s
kubectl -n kube-system rollout status ds/antrea-agent --timeout=300s

log "Waiting for node(s) Ready (CNI installed)"
kubectl wait --for=condition=Ready node --all --timeout=180s

log "Cluster '$CLUSTER_NAME' is ready."
kubectl get nodes -o wide
echo
echo "Enforcing upstream Kubernetes NetworkPolicy via Antrea."
echo "Run the e2e suite against it with: make e2e-antrea"
