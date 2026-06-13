#!/usr/bin/env bash
# Create a local kind cluster with Calico installed (idempotent).
#
# Env overrides:
#   CLUSTER_NAME    (default: telepathy-e2e)
#   CALICO_VERSION  (default: v3.32.0) — must be ≥ v3.32 for ClusterNetworkPolicy
#                    (v1alpha2 NPA support landed in v3.32; the in-process
#                    engines are also pinned to v3.32 via third_party/calico).
#   NPA_VERSION     (default: v0.2.0) — version of sigs.k8s.io/network-policy-api
#                    to source the v1alpha2 ClusterNetworkPolicy CRD from. Must
#                    match what Calico vendors (v3.32 vendors v0.2.0).
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-telepathy-e2e}"
CALICO_VERSION="${CALICO_VERSION:-v3.32.0}"
NPA_VERSION="${NPA_VERSION:-v0.2.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPERATOR_URL="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/tigera-operator.yaml"
# Upstream network-policy-api ships the v1alpha2 ClusterNetworkPolicy CRD as a
# standalone manifest. The Tigera operator deliberately does NOT install this
# CRD itself — its RBAC only requests update/delete on a *pre-existing* CRD
# (see manifests/tigera-operator.yaml: "assuming control of pre-existing CRDs,
# for example on OCP"). So we install the CRD before the operator takes over.
CNP_CRD_URL="https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/${NPA_VERSION}/config/crd/standard/policy.networking.k8s.io_clusternetworkpolicies.yaml"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# Wait until each named CRD both *exists* and is Established. `kubectl wait`
# alone returns NotFound (non-retrying) if the CRD hasn't been created yet, so
# we poll for existence first — this happens whenever a controller (here, the
# Tigera operator) installs CRDs at runtime, where the controller's pod can be
# Ready slightly before its reconcile loop has run.
wait_crd_established() {
  local timeout="$1"; shift
  for crd in "$@"; do
    local deadline=$((SECONDS + timeout))
    until kubectl get "crd/$crd" >/dev/null 2>&1; do
      [ $SECONDS -lt $deadline ] || { echo "timed out waiting for crd/$crd to be created" >&2; exit 1; }
      sleep 2
    done
    kubectl wait --for=condition=Established --timeout="${timeout}s" "crd/$crd"
  done
}

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  log "kind cluster '$CLUSTER_NAME' already exists — reusing"
else
  log "Creating kind cluster '$CLUSTER_NAME' (default CNI disabled)"
  kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/calico-kind.yaml"
fi

kubectl config use-context "kind-$CLUSTER_NAME" >/dev/null

log "Installing network-policy-api v1alpha2 ClusterNetworkPolicy CRD ($NPA_VERSION)"
# Apply before the operator so the operator's ownerReference adoption (and
# Calico's CNP watcher) sees the CRD on first reconcile. Server-side apply
# stays idempotent across reruns even after the operator stamps its owner.
kubectl apply --server-side --force-conflicts -f "$CNP_CRD_URL"
wait_crd_established 60 clusternetworkpolicies.policy.networking.k8s.io

log "Installing Tigera operator ($CALICO_VERSION)"
# Server-side apply avoids the 'metadata.annotations too long' error and keeps
# this idempotent across re-runs.
kubectl apply --server-side --force-conflicts -f "$OPERATOR_URL"

# NOTE: this manifest ships only the operator Deployment + RBAC — NO CRDs.
# The operator pod installs the operator/Calico CRDs itself once it starts, so
# we must wait for the operator to be running BEFORE waiting for the CRDs.
log "Waiting for tigera-operator deployment"
kubectl -n tigera-operator rollout status deploy/tigera-operator --timeout=180s

log "Waiting for operator CRDs to be installed by the operator"
# `rollout status` above means the operator pod is Ready, but its first
# reconcile (which creates these CRDs) may not have run yet — hence the
# wait_crd_established helper, which retries on NotFound instead of failing.
wait_crd_established 180 \
  installations.operator.tigera.io \
  apiservers.operator.tigera.io

log "Applying Calico Installation + APIServer config"
kubectl apply -f "$SCRIPT_DIR/calico-resources.yaml"

log "Waiting for calico-system to appear"
for _ in $(seq 1 60); do
  if kubectl -n calico-system get ds/calico-node >/dev/null 2>&1; then break; fi
  sleep 5
done

log "Waiting for calico-node + kube-controllers"
kubectl -n calico-system rollout status ds/calico-node --timeout=300s
kubectl -n calico-system rollout status deploy/calico-kube-controllers --timeout=300s

log "Waiting for node(s) Ready (CNI installed)"
kubectl wait --for=condition=Ready node --all --timeout=180s

log "Waiting for Calico API server (enables projectcalico.org via kubectl)"
for _ in $(seq 1 60); do
  if kubectl -n calico-system get deploy/calico-apiserver >/dev/null 2>&1; then break; fi
  sleep 5
done
kubectl -n calico-system rollout status deploy/calico-apiserver --timeout=180s || true

log "Cluster '$CLUSTER_NAME' is ready."
kubectl get nodes -o wide
echo
echo "Calico policy types available:"
kubectl api-resources --api-group=projectcalico.org 2>/dev/null | grep -iE 'networkpolic|globalnetworkpolic' || \
  echo "  (calico apiserver still warming up; re-check in a few seconds)"
echo
echo "Upstream NetworkPolicy API (v1alpha2):"
kubectl api-resources --api-group=policy.networking.k8s.io 2>/dev/null | grep -iE 'clusternetworkpolic' || \
  echo "  (CNP CRD not Established — check 'kubectl get crd clusternetworkpolicies.policy.networking.k8s.io')"
