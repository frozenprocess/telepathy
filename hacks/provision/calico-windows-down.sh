#!/usr/bin/env bash
# Tear down the Windows VM joined by calico-windows-up.sh. Leaves the kind
# cluster alone (use calico-down.sh for that).
set -euo pipefail
CLUSTER_NAME="${CLUSTER_NAME:-telepathy-e2e-calico}"
VM_NAME="${VM_NAME:-${CLUSTER_NAME}-win}"
CACHE="${CACHE:-$HOME/telepathy-windows}"
WORK="$CACHE/$VM_NAME"

virsh destroy "$VM_NAME" 2>/dev/null || true
# NOT --remove-all-storage: that deletes every volume attached to the domain,
# including the read-only install/virtio CD-ROMs (the user's Windows ISO and the
# cached virtio ISO). Undefine only, then remove just this VM's own files.
virsh undefine "$VM_NAME" --nvram 2>/dev/null || true

# The per-VM working dir holds only generated files (the qcow2 disk + the
# rendered autounattend ISO). The Windows ISO (external, user-supplied) and the
# virtio ISO (cached directly under $CACHE, a sibling of $WORK) live outside it,
# so removing $WORK never touches them. We own $WORK, so files libvirt chowned to
# libvirt-qemu still unlink.
rm -rf "$WORK"

# Best-effort: delete the node object so the cluster forgets it.
if kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null 2>&1; then
  WIN_NODE="$(kubectl get nodes -l kubernetes.io/os=windows -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$WIN_NODE" ] && kubectl delete node "$WIN_NODE" --ignore-not-found
fi
echo "Windows VM '$VM_NAME' removed (ISOs under $CACHE kept)."
