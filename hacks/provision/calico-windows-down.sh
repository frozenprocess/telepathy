#!/usr/bin/env bash
# Tear down the Windows VM joined by calico-windows-up.sh. Leaves the kind
# cluster alone (use calico-down.sh for that).
set -euo pipefail
CLUSTER_NAME="${CLUSTER_NAME:-telepathy-e2e-calico}"
VM_NAME="${VM_NAME:-${CLUSTER_NAME}-win}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CACHE="${CACHE:-$REPO_ROOT/.telepathy-windows}"
WORK="$CACHE/$VM_NAME"

virsh destroy "$VM_NAME" 2>/dev/null || true
# Undefine only. Do not pass --nvram: legacy domains may have their UEFI vars
# in libvirt's system directory, outside this VM's owned folder. New domains put
# their varstore under WORK. Never remove attached storage implicitly.
virsh undefine "$VM_NAME" 2>/dev/null || true

# Remove only generated files owned by this VM (qcow2, answer ISO, and new
# per-VM NVRAM) and cached ISOs. All default assets live under CACHE in the
# repository; a CACHE override explicitly selects a different owned root.
rm -rf "$WORK"

# Best-effort: delete the node object so the cluster forgets it.
if kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null 2>&1; then
  WIN_NODE="$(kubectl get nodes -l kubernetes.io/os=windows -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$WIN_NODE" ] && kubectl delete node "$WIN_NODE" --ignore-not-found
fi
echo "Windows VM '$VM_NAME' removed (ISOs under $CACHE kept)."
