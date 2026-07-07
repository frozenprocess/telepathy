#!/usr/bin/env bash
# Join a QEMU/libvirt Windows Server node to an existing kind+Calico cluster and
# install the Calico HNS dataplane on it — fully unattended.
#
# Assumes the Linux side is already up via calico-up.sh. This script:
#   1. reconfigures the Calico Installation for Windows (VXLAN, no BGP, HNS,
#      strictAffinity, serviceCIDRs) — see
#      https://docs.tigera.io/calico/latest/getting-started/kubernetes/windows-calico/operator
#   2. discovers the docker "kind" bridge + control-plane IP so the VM can reach
#      the API server on the same L2 segment (no cross-network routing needed)
#   3. mints a fresh kubeadm join token and bakes it, plus the k8s version and a
#      static IP, into windows-bootstrap.ps1
#   4. builds an autounattend ISO (answer file + bootstrap + virtio drivers) and
#      boots a Windows Server VM that installs containerd/kubelet and joins itself
#
# Required env:
#   WINDOWS_ISO       path to a Windows Server ISO (Eval works). Not downloadable
#                     automatically — Microsoft licensing. Get the 2022 eval from
#                     https://www.microsoft.com/evalcenter.
#
# Common overrides:
#   CLUSTER_NAME      (default: telepathy-e2e-calico) — the kind cluster to join
#   WINDOWS_VERSION   (default: 2k22) — virtio driver subfolder (2k19/2k22/2k25)
#   WINDOWS_IMAGE_NAME(default: "Windows Server 2022 Datacenter (Desktop Experience)")
#                     — WIM edition to install; list with
#                     `dism /Get-WimInfo /WimFile:<iso>/sources/install.wim`.
#                     Prefer a *Core* edition for a node (headless, smaller, no
#                     Server Manager GUI), e.g. "Windows Server 2025 SERVERDATACENTERCORE".
#   VIRTIO_VERSION    (default: 0.1.285)
#   VIRTIO_ISO_PATH   path to an existing virtio-win ISO; if set, the download is
#                     skipped and this file is used as-is (VIRTIO_VERSION ignored)
#   K8S_VERSION       (default: detected from the cluster's kubelet)
#   VM_NAME VM_VCPUS VM_RAM_MB VM_DISK_GB VM_STATIC_IP ADMIN_PASSWORD
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-telepathy-e2e-calico}"
CTX="kind-${CLUSTER_NAME}"
WINDOWS_VERSION="${WINDOWS_VERSION:-2k22}"
WINDOWS_IMAGE_NAME="${WINDOWS_IMAGE_NAME:-Windows Server 2022 Datacenter (Desktop Experience)}"
VIRTIO_VERSION="${VIRTIO_VERSION:-0.1.285}"
VM_NAME="${VM_NAME:-${CLUSTER_NAME}-win}"
VM_VCPUS="${VM_VCPUS:-4}"
VM_RAM_MB="${VM_RAM_MB:-6144}"
VM_DISK_GB="${VM_DISK_GB:-60}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Calico123!}"
# os-variant is only a hint for device defaults. Many hosts ship an osinfo db
# with no Windows entries, where a bare short-id (win2k22) hard-errors — so
# default to detect+non-fatal. Override with e.g. OS_VARIANT=win2k25 if your db
# has it (osinfo-query os | grep win).
OS_VARIANT="${OS_VARIANT:-detect=on,require=off}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# NOT under ~/.cache: system libvirt runs qemu as libvirt-qemu, which can't
# traverse ~/.cache (mode 700) to open the disk/ISOs — "Permission denied". A
# dedicated ~/telepathy-windows we chmod 0755 is reachable ($HOME is 0751/0755).
CACHE="${CACHE:-$HOME/telepathy-windows}"
WORK="$CACHE/$VM_NAME"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

for t in kubectl kind docker virt-install virsh qemu-img; do
  command -v "$t" >/dev/null || die "need '$t' on PATH"
done
# genisoimage or mkisofs — either builds the answer-file ISO.
MKISO="$(command -v genisoimage || command -v mkisofs)" || die "need genisoimage or mkisofs"
[ -n "${WINDOWS_ISO:-}" ] || die "set WINDOWS_ISO to a Windows Server ISO path"
[ -f "$WINDOWS_ISO" ]     || die "WINDOWS_ISO not found: $WINDOWS_ISO"
kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME" || die "kind cluster '$CLUSTER_NAME' not found — run calico-up.sh first"
kubectl config use-context "$CTX" >/dev/null

mkdir -p "$CACHE" "$WORK"
# qemu runs as libvirt-qemu (system libvirt); it must be able to traverse into
# these dirs to open the disk/ISOs. umask can leave them 0700, so force 0755.
chmod 0755 "$CACHE" "$WORK"
# If $HOME itself isn't other-executable, even a 0755 subdir is unreachable by
# libvirt-qemu — warn and point at the override.
case "$(stat -c '%A' "$HOME")" in
  *x) ;;
  *) echo ">> warning: $HOME is not other-executable; libvirt-qemu may not reach $CACHE — set CACHE=<a traversable path>" >&2 ;;
esac

# --- 1. Reconfigure Calico for the Windows/HNS dataplane -------------------
# The Linux default (calico-resources.yaml) is VXLANCrossSubnet + BGP; Windows
# requires plain VXLAN, BGP disabled. These patches are idempotent.
log "Patching Calico Installation for Windows (VXLAN, no BGP, HNS)"
kubectl patch installation default --type=json \
  -p='[{"op":"replace","path":"/spec/calicoNetwork/ipPools/0/encapsulation","value":"VXLAN"}]'
kubectl patch installation default --type=merge \
  -p='{"spec":{"calicoNetwork":{"bgp":"Disabled","windowsDataplane":"HNS"}}}'

# serviceCIDRs must match the apiserver's --service-cluster-ip-range. kind's
# default is 10.96.0.0/16; read it back rather than assume.
SVC_CIDR="$(kubectl -n kube-system get pod -l component=kube-apiserver \
  -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null \
  | tr ',' '\n' | sed -n 's/.*service-cluster-ip-range=//p' | tr -d '"]' )"
SVC_CIDR="${SVC_CIDR:-10.96.0.0/16}"
log "Service CIDR: $SVC_CIDR"
kubectl patch installation default --type=merge \
  -p="{\"spec\":{\"serviceCIDRs\":[\"${SVC_CIDR}\"]}}"

log "Enabling strict IPAM affinity (required for Windows)"
kubectl patch ipamconfigurations default --type=merge \
  -p='{"spec":{"strictAffinity":true}}'

# --- 2. Discover the kind docker network + control-plane -------------------
# kind attaches every node container to a shared docker network named "kind";
# the VM joins the same bridge so node/API traffic is a single L2 hop.
CP_CONTAINER="${CLUSTER_NAME}-control-plane"
BRIDGE="br-$(docker network inspect kind -f '{{.Id}}' | cut -c1-12)"
ip link show "$BRIDGE" >/dev/null 2>&1 || die "kind bridge $BRIDGE not found — is the 'kind' docker network up?"
# kind is often dual-stack, so IPAM.Config[0] may be IPv6 — pick the IPv4 entry
# explicitly (the Windows node joins over IPv4).
V4="$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}},{{.Gateway}}{{"\n"}}{{end}}' | grep -E '^[0-9]+\.' | head -1)"
[ -n "$V4" ] || die "no IPv4 subnet on docker 'kind' network"
SUBNET="${V4%%,*}"
GATEWAY="${V4##*,}"
MTU="$(docker network inspect kind -f '{{index .Options "com.docker.network.driver.mtu"}}')"
MTU="${MTU:-1500}"
CP_IP="$(docker inspect "$CP_CONTAINER" -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')"
PREFIX="${SUBNET##*/}"
# Static IP high in the subnet, clear of docker's sequential-from-.2 allocation.
# ponytail: naive "gateway with last octet -> 250"; override VM_STATIC_IP if the
# subnet isn't a /16-ish IPv4 or .250 is taken.
VM_STATIC_IP="${VM_STATIC_IP:-$(echo "$GATEWAY" | sed 's/\.[0-9]*$/.250/')}"
log "kind bridge=$BRIDGE subnet=$SUBNET gw=$GATEWAY mtu=$MTU cp=$CP_IP vm=$VM_STATIC_IP"

# --- 3. Mint the join token and detect the k8s version ---------------------
log "Creating kubeadm join token on $CP_CONTAINER"
JOIN_CMD="$(docker exec "$CP_CONTAINER" kubeadm token create --print-join-command)"
[ -n "$JOIN_CMD" ] || die "empty join command"
# The join, kubeadm-config, and the generated kubelet kubeconfig all reference
# the control-plane by hostname, which the VM (DNS = public resolvers, not
# docker's) can't resolve. bootstrap.ps1 adds a hosts entry ($CP_HOST -> $CP_IP)
# so the hostname works everywhere. CP_HOST is the control-plane's kube node name.
CP_HOST="$CP_CONTAINER"
K8S_VERSION="${K8S_VERSION:-$(kubectl get node "$CP_CONTAINER" -o jsonpath='{.status.nodeInfo.kubeletVersion}')}"
log "Kubernetes version: $K8S_VERSION"

# calico-node-windows needs to reach the API server directly (Windows kube-proxy
# may not be up when it first starts). Point it at the control-plane IP on the
# shared bridge — reachable from the VM without kube-proxy.
log "Creating kubernetes-services-endpoint ConfigMap ($CP_IP:6443)"
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubernetes-services-endpoint
  namespace: tigera-operator
data:
  KUBERNETES_SERVICE_HOST: "${CP_IP}"
  KUBERNETES_SERVICE_PORT: "6443"
EOF

# Windows kube-proxy runs as a hostprocess DaemonSet from the control plane.
log "Applying Windows kube-proxy DaemonSet"
curl -fsSL "https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/hostprocess/calico/kube-proxy/kube-proxy.yml" \
  | sed "s/KUBE_PROXY_VERSION/${K8S_VERSION}/g" | kubectl apply -f - || \
  echo ">> note: kube-proxy apply failed (may already exist or need manual version); continuing"

# --- 4. Fetch virtio drivers -----------------------------------------------
# VIRTIO_ISO_PATH points at an already-downloaded virtio-win ISO; when set we use
# it as-is and skip the download (offline / pre-cached / custom version).
if [ -n "${VIRTIO_ISO_PATH:-}" ]; then
  [ -f "$VIRTIO_ISO_PATH" ] || die "VIRTIO_ISO_PATH not found: $VIRTIO_ISO_PATH"
  VIRTIO_ISO="$VIRTIO_ISO_PATH"
  log "Using virtio ISO: $VIRTIO_ISO (download skipped)"
else
  VIRTIO_ISO="$CACHE/virtio-win-${VIRTIO_VERSION}.iso"
  VIRTIO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-${VIRTIO_VERSION}-1/virtio-win-${VIRTIO_VERSION}.iso"
  if [ ! -f "$VIRTIO_ISO" ]; then
    log "Downloading virtio-win-${VIRTIO_VERSION}.iso"
    curl -fL "$VIRTIO_URL" -o "$VIRTIO_ISO.part" && mv "$VIRTIO_ISO.part" "$VIRTIO_ISO"
  fi
fi

# --- 5. Render the answer file + bootstrap into an ISO ---------------------
# The join command carries the API server IP already; on Windows we invoke the
# kubelet-side kubeadm and (for <1.25) the containerd npipe socket in bootstrap.
log "Rendering autounattend + bootstrap"
ISODIR="$WORK/iso"; rm -rf "$ISODIR"; mkdir -p "$ISODIR"

sed -e "s|@@IMAGE_NAME@@|${WINDOWS_IMAGE_NAME}|g" \
    -e "s|@@ADMIN_PASSWORD@@|${ADMIN_PASSWORD}|g" \
    -e "s|@@WINDOWS_VERSION@@|${WINDOWS_VERSION}|g" \
    "$SCRIPT_DIR/autounattend.xml" > "$ISODIR/autounattend.xml"

# JOIN_CMD may contain slashes/ampersands — write via a delimiter awk-free sed
# using a control char unlikely to appear, then the rest with normal subs.
esc() { printf '%s' "$1" | sed 's/[&|]/\\&/g'; }
sed -e "s|@@JOIN_COMMAND@@|$(esc "$JOIN_CMD")|g" \
    -e "s|@@K8S_VERSION@@|${K8S_VERSION}|g" \
    -e "s|@@STATIC_IP@@|${VM_STATIC_IP}|g" \
    -e "s|@@PREFIX@@|${PREFIX}|g" \
    -e "s|@@GATEWAY@@|${GATEWAY}|g" \
    -e "s|@@MTU@@|${MTU}|g" \
    -e "s|@@CP_HOST@@|${CP_HOST}|g" \
    -e "s|@@CP_IP@@|${CP_IP}|g" \
    "$SCRIPT_DIR/windows-bootstrap.ps1" > "$ISODIR/bootstrap.ps1"

ANSWER_ISO="$WORK/autounattend.iso"
# rm first: libvirt's dynamic ownership may have left a prior run's ISO/disk
# owned by libvirt-qemu, which we (as $USER) can't overwrite — but can unlink,
# since $WORK is ours. Each run is a fresh install, so a stale disk is dropped too.
rm -f "$ANSWER_ISO"
"$MKISO" -quiet -J -r -V AUTOUNATTEND -o "$ANSWER_ISO" "$ISODIR"

# --- 6. Boot the VM --------------------------------------------------------
DISK="$WORK/${VM_NAME}.qcow2"
virsh destroy "$VM_NAME" 2>/dev/null || true
virsh undefine "$VM_NAME" --nvram 2>/dev/null || true
rm -f "$DISK"
qemu-img create -f qcow2 "$DISK" "${VM_DISK_GB}G" >/dev/null

log "Booting Windows VM '$VM_NAME' (virtio disk+NIC on $BRIDGE)"
# Three CDs: Windows install, virtio drivers, our answer file. Disk+NIC are
# virtio; drivers are injected at WinPE via autounattend DriverPaths (drive E:,
# ponytail: fixed letter — see autounattend.xml if Setup can't find the disk).
# boot.order makes OVMF try the install CD (1) before the blank disk (2) — without
# it OVMF's default order omits the CD and the first boot dead-ends at "no bootable
# device". On later reboots the CD's "press any key" prompt times out (we only
# press during the initial window below) and control falls through to the disk's
# Windows Boot Manager, which Setup has by then installed.
virt-install \
  --name "$VM_NAME" \
  --os-variant "$OS_VARIANT" \
  --vcpus "$VM_VCPUS" --memory "$VM_RAM_MB" \
  --cpu host-passthrough \
  --disk "path=$DISK,bus=virtio,boot.order=2" \
  --disk "path=$WINDOWS_ISO,device=cdrom,bus=sata,readonly=on,boot.order=1" \
  --disk "path=$VIRTIO_ISO,device=cdrom,bus=sata,readonly=on" \
  --disk "path=$ANSWER_ISO,device=cdrom,bus=sata,readonly=on" \
  --network "bridge=$BRIDGE,model=virtio,mtu.size=$MTU" \
  --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 \
  --graphics vnc,listen=0.0.0.0 \
  --boot uefi \
  --noautoconsole

# Auto-press the firmware's "Press any key to boot from CD or DVD" prompt, which
# only appears in the first ~seconds of the first boot. Spamming space for ~45s
# clears it hands-off; the keys are harmless once Setup's GUI-less unattend runs.
log "Kicking the CD boot prompt (auto-keypress for 45s)"
for _ in $(seq 1 45); do virsh send-key "$VM_NAME" --codeset linux 57 >/dev/null 2>&1 || true; sleep 1; done &

log "VM is installing unattended. Watch the console with:"
echo "    virt-viewer --connect qemu:///system $VM_NAME"
echo
log "Waiting for the Windows node to register + become Ready (up to 30m)..."
WIN_NODE=""
for _ in $(seq 1 180); do
  WIN_NODE="$(kubectl get nodes -l kubernetes.io/os=windows -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$WIN_NODE" ] && kubectl wait --for=condition=Ready "node/$WIN_NODE" --timeout=10s >/dev/null 2>&1 && break
  sleep 10
done
[ -n "$WIN_NODE" ] || die "Windows node never registered — check the VM console and C:\\bootstrap.log"

log "Windows node '$WIN_NODE' is Ready. Waiting for calico-node-windows..."
kubectl rollout status -n calico-system ds/calico-node-windows --timeout=600s || \
  echo ">> note: calico-node-windows not Ready yet; check 'kubectl logs -n calico-system -l k8s-app=calico-node-windows -c node'"

kubectl get nodes -o wide
log "Done. Windows node '$WIN_NODE' joined via $VM_STATIC_IP on $BRIDGE."
