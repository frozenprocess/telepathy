#!/usr/bin/env bash
# Delete the local kind cluster.
set -euo pipefail
CLUSTER_NAME="${CLUSTER_NAME:-telepathy-e2e}"
kind delete cluster --name "$CLUSTER_NAME"
