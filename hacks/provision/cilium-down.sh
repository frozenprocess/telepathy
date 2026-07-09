#!/usr/bin/env bash
# Delete the local Cilium kind cluster.
set -euo pipefail
CLUSTER_NAME="${CLUSTER_NAME:-telepathy-e2e-calico-cilium}"
kind delete cluster --name "$CLUSTER_NAME"
