# Telepathy E2E: dataplane vs engine

This package runs each `e2e/testdata/<case>/` on a **real kind + Calico cluster** and
compares the measured allow/deny verdict against the in-process engine's
prediction. It is the ground-truth counterpart to `make verify-all`, which only
checks the engine against hand-authored `expect` values.

## Run it

```bash
make e2e                              # bring up the cluster (hacks/provision/calico-up.sh) + run every applicable case
make e2e CASE=np-deny-all-ingress     # run a single case
make e2e CASE=gnp-                    # run every case whose name matches (regex passed to -run)
E2E_INCLUDE_HEP=1 make e2e            # also run the HostEndpoint cases (see below)
E2E_OS=windows make e2e               # schedule the workload pods on a Windows node (see below)
```

Or directly, against an already-running cluster:

```bash
CLUSTER_NAME=telepathy-e2e TELEPATHY_BIN=$(pwd)/bin/telepathy \
  go test -tags e2e -timeout 60m -count=1 ./e2e/... -v
```

The cluster is left running so it can be reused across runs; tear it down with
`hacks/provision/calico-down.sh`.

## How a case runs

1. Parse `topology.yaml` / `assertions.yaml` / `policy.yaml` with the `api`
   package (the same types the engine uses — no duplicate schema).
2. Materialize the topology: `Namespace`s, `ServiceAccount`s, `Pod`s (each
   running a single **agnhost** container — a TCP/UDP/SCTP server that also
   supplies busybox `ping` for ICMP probes), `Service`s, Calico
   `(Global)NetworkSet`s and `HostEndpoint`s.
3. Wait for pods Ready, harvest their real IPs, and build a fictional→real IP
   map. Rewrite the topology, netsets, HEP IPs, and any policy CIDR that
   contains a fictional endpoint IP so **both** the engine and the cluster
   evaluate identical real-IP inputs.
4. Apply the rewritten policy, run the engine over the rewritten topology
   (`telepathy test -json`), and probe every assertion's flow with
   `agnhost connect` (tcp/udp/sctp) or `ping` (icmp).
5. Compare per assertion. The test **fails on any engine≠cluster disagreement**.
   Rows where `engine==cluster` but `≠expect` are reported as `expect?` — a
   questionable assertion, not an engine bug — and are not fatal.

## Debugging a failure

A failing row prints `DIFF (engine != cluster)` or `ERR` in the comparison
table, followed by the **raw probe output** for that row (`agnhost connect` /
`ping`) — the dataplane's actual words, not just the allow/deny it was reduced
to. That alone often explains an `ERR`.

For a `DIFF` you usually want the full picture. Set `E2E_ARTIFACTS=<dir>` and the
harness snapshots each failed case **before teardown deletes it** into
`<dir>/<case>/`:

```bash
E2E_ARTIFACTS=$(pwd)/e2e-artifacts make e2e CASE=gnp-order-deny-before-allow
```

Each case directory contains:

- `applied-policy.yaml` / `engine-topology.yaml` — the exact IP-rewritten inputs
  the cluster and the engine saw. Re-run the engine offline with
  `telepathy test -policy applied-policy.yaml < engine-topology.yaml` to
  reproduce its side of the disagreement without a cluster.
- `engine-report.json` / `engine-stderr.txt` — the engine's per-assertion
  verdicts and any diagnostics it logged.
- `comparison.txt` — the three-way table plus the failed rows' probe output.
- `applied-policies.yaml` — the policy objects as the apiserver sees them (the
  authoritative view of what the dataplane is enforcing).
- `cluster-state.txt` — `get pods -o wide`, `describe pods`, and recent events
  for the case namespaces.
- `felix-logs.txt` — Felix's recent logs from the `calico-node` pod on each node
  (which policy it resolved, any programming errors). Calico only.
- `dataplane-rules.txt` — the programmed packet-filter ruleset
  (`iptables-save` / `ip6tables-save` / `nft list ruleset`) read straight from
  each kind node — the `cali-*` chains that actually allow/deny the probe. This
  is the ground truth a `DIFF` is a disagreement about. Calico only.

Capture is off by default (no slowdown / no artifacts on green runs); only
failed cases write anything.

### Poking at a failure live (`E2E_KEEP=1`)

When the dump files aren't enough, `E2E_KEEP=1` leaves a **failed** case's
resources (namespaces, pods, policy, HEPs, netsets) in place instead of tearing
them down, so you can inspect the live scene with `kubectl`:

```bash
E2E_KEEP=1 make e2e CASE=gnp-order-deny-before-allow
# ...then, against the kept cluster:
kubectl --context kind-telepathy-e2e-calico-calico get pods,networkpolicies,globalnetworkpolicies -A
kubectl --context kind-telepathy-e2e-calico-calico exec -n <ns> <pod> -c agnhost -- /agnhost connect <ip>:<port> --protocol=tcp
```

Use it with a **single `CASE=`** — kept namespaces/pods would otherwise collide
with later cases reusing the same names. Successful cases always tear down.
Clean up the kept resources (and, for a HEP case, the cluster-wide narrowed
failsafes it leaves behind) with `hacks/provision/calico-down.sh` or by deleting
the namespaces by hand.

## Prerequisites

- `kubectl`, `kind`, and `docker` on `PATH`.
- The `sctp` kernel module for SCTP cases: `sudo modprobe sctp`. `make e2e`
  prints a note if it's missing.
- Container image (overridable): `AGNHOST_IMAGE`
  (`registry.k8s.io/e2e-test-images/agnhost:2.52`). It serves L4 and provides
  busybox `ping` for ICMP — no separate tools image. `E2E_OS=windows` needs a
  Windows agnhost variant matching the node build (its image has no `ping`, so
  ICMP is skipped there).

## HostEndpoint cases (opt-in)

The three `gnp-hep-*` cases attach Calico `HostEndpoint`s and **narrow Calico's
failsafe host ports to a control-plane-only set** (apiserver, etcd, kubelet,
ssh, BGP, DNS, **Typha**) cluster-wide for the duration of the case. Calico's
failsafe rules unconditionally allow their listed ports, so the probe ports must
be absent for the HostEndpoint policy to govern them — but the apiserver/etcd/
kubelet ports stay open so the node remains reachable, and **Typha's 5473 stays
open in both directions**: a `*`-interface HEP subjects the node's own traffic
to policy, and dropping `calico-node ↔ calico-typha` severs Typha discovery and
crash-loops calico-node cluster-wide. This is opt-in via
`E2E_INCLUDE_HEP=1`; the harness restores the failsafe defaults and flushes
conntrack in teardown even on failure. Host actors (`host/<name>`) are realized
as `hostNetwork` pods pinned to the node, so host-originated/terminated traffic
is exercised through the same probe path as pod traffic.

**HostEndpoints are always relocated to a worker node**, never the
control-plane, regardless of the topology's `node:` value — an enforced host
policy must not be able to sever the API server / etcd that run on the
control-plane (this wedged the cluster during development). The engine topology
is re-marshaled from the mutated Request for these cases so the engine and the
dataplane evaluate identical node placement.

### Quarantined flows (`quarantine.yaml`)

A case dir may contain an optional `quarantine.yaml` listing flows the *cluster*
can't faithfully reproduce — environment limits, not engine bugs. Each entry is
`{from, to, reason}`. The harness records these rows but does **not** probe or
score them (they show as `QUARANTINED` in the table). `make verify-all` (engine
vs authored `expect`) still covers them in full.

The motivating example is `gnp-hep-donottrack-database-to-host`: a `pod ->
node-IP` flow (a database pod reaching the HostEndpoint's node address) is
source-NAT'd to the source node's IP by the IP pool's `natOutgoing`, because the
node IP is outside the pod CIDR. The HostEndpoint never sees the pod's
`app == 'database'` label, so the dataplane allows the flow no matter what the
policy says; the engine correctly models the policy. The two legitimately
disagree for reasons unrelated to engine fidelity, so those two flows are
quarantined.

## North-south cases: external observer + NodePort (`externalProbe`)

preDNAT host policy is a *north-south* construct: it governs traffic entering a
node from outside, before kube-proxy DNAT. To exercise it faithfully a case
opts in with `externalProbe: true` in `meta.yaml`, which changes how two things
are realized:

- **`role: external` endpoints become off-cluster Docker containers.** Instead
  of a pod, the harness launches an agnhost container on the kind Docker network
  (`telepathy-ext-<id>`), harvests its IP, and probes from it via `docker exec`.
  The observer's real IP is fed into the IP rewriter, so the topology's external
  endpoint **and** any policy `source.nets` referencing it resolve to that IP —
  the engine then evaluates the same source the dataplane sees.
- **NodePort Services give an externally routable target.** A `ServiceInput`
  with `type: NodePort` (and an optional `nodePort:` per port) is realized as a
  NodePort Service; an external→`svc/<ns>/<name>` assertion is probed at
  `<node-IP>:<nodePort>` (the only path reachable from off-cluster — pod and
  ClusterIPs are not).

The engine does **not** model NodePort/DNAT, so these cases must key their
preDNAT rule on the **source CIDR** (the observer), which is invariant under
DNAT: the engine evaluates the flow to the backend pod, the dataplane evaluates
`node-IP:nodePort` before DNAT, and both agree because the source match doesn't
change across the DNAT. A destination/port-keyed preDNAT rule would *not* line
up and needs engine support first.

The reference case is `gnp-hep-prednat-nodeport-block-external`: two observers
(one source CIDR denied by a preDNAT GlobalNetworkPolicy, one allowed) reach a
NodePort-fronted backend; the deny fires before DNAT on the entry node. Like all
HostEndpoint cases it requires `E2E_INCLUDE_HEP=1`.

## Windows nodes (`E2E_OS=windows`)

Policies can be exercised against the Calico **Windows/HNS** dataplane by joining
a Windows node to the kind cluster and pinning the workload pods to it.

### 1. Provision a Windows node

`kind` nodes are Linux containers; a Windows node has to be a real VM. The
`calico-windows-up.sh` provisioner boots a **QEMU/libvirt Windows Server VM**,
attaches it to the docker `kind` bridge (so it shares the node subnet — no
cross-network routing), and joins it, fully unattended:

```bash
make e2e-windows \
  WINDOWS_ISO=/path/to/windows-server-2025.iso \
  WINDOWS_VERSION=2k25 \
  WINDOWS_IMAGE_NAME="Windows Server 2025 SERVERDATACENTERCORE"
```

It: reconfigures Calico for Windows (VXLAN, BGP off, `windowsDataplane: HNS`,
strict IPAM affinity), fetches the virtio drivers (or reuses `VIRTIO_ISO_PATH`),
renders an unattended-install answer file with a fresh `kubeadm` join token baked
in, boots the VM, and waits for the node to go `Ready` with `calico-node-windows`
running. Tear it down (leaving the kind cluster, keeping the ISOs) with
`make e2e-windows-down`.

Requirements beyond the base ones: **libvirt** (`virt-install`, `virsh`,
`qemu-img`), **`genisoimage`**/`mkisofs`, and a **Windows Server ISO** (not
auto-downloadable — Microsoft licensing; Server Core is preferred: headless,
smaller). See the header of `hacks/provision/calico-windows-up.sh` for every
env override.

### 2. Run cases on it

```bash
E2E_OS=windows make e2e CASE=<case>
```

`E2E_OS=windows` stamps `kubernetes.io/os: windows` on every workload pod's
`nodeSelector` (unless the endpoint declares its own), so pods land on the
Windows node. Pods are named `<endpoint>-windows` and the report labels each
actor with its OS (`prod/frontend[windows]`) so placement is visible at a glance.

The testdata cases pin pods to Linux nodes (`node: ...-worker`) to spread them
across nodes; under `E2E_OS=windows` those pins are **dropped** (a `nodeName`
would override the OS nodeSelector), so all pods co-locate on the single Windows
node. This means Windows runs exercise **same-node** enforcement only — no
cross-node distribution (you'd need multiple Windows nodes for that).

Two things to know:

- **Windows-compatible image.** Set `AGNHOST_IMAGE` to a Windows agnhost variant
  whose base build matches the node (Server 2025 = `ltsc2025`) or the pods won't
  start. The Windows agnhost image has **no `ping`**, so ICMP assertions are
  **skipped** on Windows (L4 TCP/UDP/SCTP still run).
- **Don't re-provision under it.** `make e2e` first runs `calico-up.sh`, which
  re-applies `calico-resources.yaml` (`VXLANCrossSubnet`) — reverting the plain
  **`VXLAN`** encapsulation Windows HNS requires (on a single-subnet kind cluster
  CrossSubnet means *no* encapsulation, and HNS drops the unencapsulated pod
  traffic). After `make e2e-windows`, run the tests against the existing cluster
  directly instead:

  ```bash
  CLUSTER_NAME=telepathy-e2e-calico E2E_PROVIDER=calico E2E_OS=windows \
    TELEPATHY_BIN=$(pwd)/bin/telepathy go test -tags e2e -timeout 60m -count=1 ./e2e/... -v
  ```

## Known limitations

- **Windows pod↔Linux pod traffic needs plain `VXLAN`.** The IP pool must be
  `VXLAN` (not `VXLANCrossSubnet`) for HNS overlay traffic to cross between Linux
  and Windows nodes; `calico-windows-up.sh` sets this, but a subsequent
  `calico-up.sh`/`make e2e` reverts it (see above). ICMP is unavailable on
  Windows (no `ping` in the Windows agnhost image).
- **IPv4 only.** The IP-remap token matcher (`ipmap.go`) handles IPv4
  addresses/CIDRs; an IPv6 e2e/testdata case would need it widened.
- **One port per protocol per case.** agnhost's netexec serves one TCP, one UDP,
  and one SCTP port; if a case probed the same protocol on two ports the harness
  serves the first and logs a warning (no current case does this).
- **A referenced CIDR that contains two endpoints** collapses to the first
  (warned). No current case puts two endpoints in one referenced CIDR.
- Cases run **serially** with full teardown between them — the topologies reuse
  namespace names (`prod`, `dev`) and HEP cases mutate node-wide state, so
  parallel execution on one cluster is unsafe.
