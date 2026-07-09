#!/usr/bin/env bash
# Create a local kind cluster with Cilium installed (idempotent).
#
# Cilium enforces upstream Kubernetes NetworkPolicy (plus its own CRDs), which
# is what the out-of-process Cilium engine (engines/cilium) predicts via its
# real pkg/policy. The e2e harness then compares the engine's prediction against
# this cluster's real connectivity for every k8s-flavored e2e/testdata case
# (see `make e2e PROVIDER=cilium`).
#
# This is a SEPARATE cluster from the Calico/Antrea e2e ones (a node runs only
# one CNI), hence the distinct default CLUSTER_NAME.
#
# Cilium ships no single all-in-one manifest like Antrea, so we install via its
# Helm chart (requires `helm` on PATH). The chart version tracks the app
# version, so CILIUM_VERSION drives both the chart and the image tag.
#
# Env overrides:
#   CLUSTER_NAME    (default: telepathy-e2e-calico-cilium)
#   CILIUM_VERSION  (default: 1.19.5) — kept in step with the engine's pinned
#                    Cilium source tree (Makefile CILIUM_VERSION, minus the "v")
#                    so the dataplane and the engine implement the same semantics.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-telepathy-e2e-calico-cilium}"
# Accept a leading "v" (Makefile pins vX.Y.Z) but Helm wants the bare version.
CILIUM_VERSION="${CILIUM_VERSION:-1.19.5}"
CILIUM_VERSION="${CILIUM_VERSION#v}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

command -v helm >/dev/null || { echo "helm not found on PATH (needed to install Cilium)"; exit 1; }

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  log "kind cluster '$CLUSTER_NAME' already exists — reusing"
else
  log "Creating kind cluster '$CLUSTER_NAME' (default CNI disabled)"
  kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/cilium-kind.yaml"
fi

kubectl config use-context "kind-$CLUSTER_NAME" >/dev/null

log "Installing Cilium ($CILIUM_VERSION) via Helm"
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
helm repo update cilium >/dev/null
# --reuse-values-free upgrade --install keeps this idempotent across re-runs.
# ipam.mode=kubernetes uses the podCIDR kind assigns (matches cilium-kind.yaml);
# the defaults (kube-proxy present, no BPF host-routing) are the simplest setup
# that enforces NetworkPolicy correctly, which is all the e2e harness needs.
helm upgrade --install cilium cilium/cilium \
  --version "$CILIUM_VERSION" \
  --namespace kube-system \
  --set image.pullPolicy=IfNotPresent \
  --set ipam.mode=kubernetes

log "Waiting for cilium-operator + cilium agent"
kubectl -n kube-system rollout status deploy/cilium-operator --timeout=300s
kubectl -n kube-system rollout status ds/cilium --timeout=300s

log "Waiting for node(s) Ready (CNI installed)"
kubectl wait --for=condition=Ready node --all --timeout=180s

log "Cluster '$CLUSTER_NAME' is ready."
kubectl get nodes -o wide
echo
echo "Enforcing upstream Kubernetes NetworkPolicy via Cilium."
echo "Run the e2e suite against it with: make e2e PROVIDER=cilium"
