# Securing the e2e cluster — best practices, verified by the engine

This is the [*best-practices-for-securing-a-Kubernetes-environment*][ref] guide,
rebuilt as a telepathy case. Same story — default-deny the cluster, then re-open
only the flows Calico's control plane needs — but every policy is checked by the
**engine** (Felix's own code) before it ever touches a cluster:

```bash
telepathy test -assert assertions.yaml -policy policy.yaml < topology.yaml
# 8 passed, 0 failed
make verify-all CASE=secure-e2e-cluster    # same thing, through the harness
```

The point of doing it in telepathy: three of the presentation's policies look
right but enforce nothing. The engine denies the flows they were meant to open,
so you find out here instead of at 2am. Each is fixed below and the fix is
labelled `*** CORRECTED ***` in [`policy.yaml`](policy.yaml).

## The story

Lower Calico `order` wins; Kubernetes NetworkPolicies get an implicit `1000`, so
the default-deny sits at `2000` (last) and every allow at `1000` (first).

1. **Default-deny every pod** — `deny-app-policy`, a GlobalNetworkPolicy with
   `namespaceSelector: has(projectcalico.org/name)` and both types, no rules.
   This is the whole cluster locked, control plane included.
2. **Permit DNS** — every pod may egress to `telepathy.tigera.io/app == "kube-dns"` on 53.
3. **calico-apiserver → kube-apiserver** on 6443.
4. **calico components → calico-apiserver** on 5443.

Then the assertions prove the four flows above survive **and** that the app
namespace, the attacker, and everyone-but-the-components stay shut out.

## What the engine caught

**1. `permit-dns` opened only half the path.** The presentation allows pod
*egress* to kube-dns and stops. But `deny-app-policy` also denied coredns's
*ingress*, so the query never lands. Telepathy denies `frontend → coredns` until
you add the ingress leg (`permit-dns-ingress`). DNS needs **both** legs.

**2. `calico-apiserver-to-kapi` targeted a pod that doesn't exist.** The original
selects `has(kubernetes.io/os)` + `namespaceSelector: global()`:

```yaml
destination:
  selector: has(kubernetes.io/os)   # a NODE label — never on a pod
  namespaceSelector: global()
  ports: [6443]
```

`kubernetes.io/os` is a **node** label, and the kube-apiserver is
**host-networked** — a Calico *HostEndpoint*, not a WorkloadEndpoint any pod
selector can hit. The engine confirms an egress `destination.selector` only
matches workload endpoints, so this rule allows nothing. The fix targets the
control-plane **node IP** and adds the host-side ingress the HostEndpoint needs
once policy selects it:

```yaml
destination:
  nets: [172.18.0.5/32]   # the control-plane node
  ports: [6443]
```

**3. The component→apiserver hop crossed a namespace boundary silently.**
`calico-kube-controllers`/`typha` run in `calico-system`; `calico-apiserver`
runs in the `calico-apiserver` namespace. In a **namespaced** `NetworkPolicy` a
bare rule `selector` (source *or* destination) is scoped to the policy's own
namespace — so a `calico-system` policy selecting
`telepathy.tigera.io/app == "calico-apiserver"` matches nothing, and neither does
the apiserver's ingress selecting the components back. Telepathy denies both legs.
The fix makes both a `GlobalNetworkPolicy`, whose selectors are cluster-wide.

## Why the stand-ins are labelled `telepathy.tigera.io/app`, not `k8s-app`

On a real cluster these agnhost stand-ins are applied into the **actual**
`calico-system` / `kube-system` namespaces. A Service adopts any pod wearing its
selector labels in its namespace — so a stand-in labelled `k8s-app: calico-typha`
would join the live `calico-typha` Service and break `calico-node`'s Typha
discovery cluster-wide; `k8s-app: kube-dns` would poison the real kube-dns
Service. The stand-ins therefore use a telepathy-owned label key no live Service
selects on (keeping the recognizable values), and the policies select on that key.
Rule of thumb for any calico-flavored case that reuses a real namespace: **never
give a stand-in a live component's Service-selector label.**

## Files

| file | what |
|---|---|
| [`topology.yaml`](topology.yaml) | the cluster: calico-system / calico-apiserver / kube-system / demo pods, plus the kube-apiserver as a control-plane HostEndpoint |
| [`policy.yaml`](policy.yaml) | the four-step hardening, corrections marked `*** CORRECTED ***` |
| [`assertions.yaml`](assertions.yaml) | the intent: 4 control-plane flows allowed, 4 isolation flows denied |
| [`meta.yaml`](meta.yaml) | `flavor: calico`; needs 3 nodes for a full `make e2e` (HostEndpoint) |

[ref]: https://github.com/frozenprocess/Tigera-Presentations/tree/master/2023-03-30.container-and-Kubernetes-security-policy-design/04.best-practices-for-securing-a-Kubernetes-environment
