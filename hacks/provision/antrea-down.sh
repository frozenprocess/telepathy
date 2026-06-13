#!/usr/bin/env bash
# Delete the local Antrea kind cluster.
set -euo pipefail
CLUSTER_NAME="${CLUSTER_NAME:-telepathy-e2e-calico-antrea}"
kind delete cluster --name "$CLUSTER_NAME"
