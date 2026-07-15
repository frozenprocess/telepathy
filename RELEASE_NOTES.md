# Telepathy v0.1.0 - It's not a dream anymore!

**Know what a NetworkPolicy does before you merge it, no cluster required.**

Telepathy evaluates Kubernetes & Calico NetworkPolicies by running the CNI's
*own* policy engine against a topology you describe in YAML. In milliseconds,
with no Kubernetes, no CNI, and no nodes, it tells you which pod can talk to
which resources and renders the dataplane rules (iptables/nftables, eBPF, Windows HNS)
that would actually be programmed.

This is the first cut. Everything below is new.

## Highlights

- **Three modes over one stdin→stdout engine.** `evaluate` produces a
  connectivity matrix (a pair is `allow` only if it clears both egress and
  ingress); `test` runs assertions as a CI gate with a non-zero exit on
  failure; `diff` reports only the flows a change *opened* (deny→allow, new
  exposure) or *closed* (allow→deny, possible outage). _(`58b0e42`, `3c03ee2`)_

- **Pluggable across CNIs.** A vendor-neutral request/response JSON schema
  (the `api` module) sits behind a `Provider` interface, selected at runtime
  with `-provider`. Each engine drives the CNI's real code offline.
  - **Calico** (default) — builds a Felix `CalculationGraph` and walks each
    ordered pair through `app-policy/checker.Evaluate` for both directions.
    Supports k8s `networking.k8s.io/v1` and Calico `projectcalico.org/v3`
    (Global)NetworkPolicy, Tier, NetworkSet, HostEndpoint, and Service/
    ServiceAccount selectors.
  - **Antrea** — a separate `telepathy-engine-antrea` binary (own Go module,
    Antrea's native dependency versions) reached over the JSON contract. Drives
    Antrea's real `grouping.GroupEntityIndex` for k8s NetworkPolicy. A
    cross-process test asserts it agrees with the Calico engine flow-for-flow.
  - **Cilium** — an out-of-process engine driving Cilium's real `pkg/policy`
    (v1.19.5) for k8s NetworkPolicy; `-provider cilium`.

  _(`8f677bc`, `0fe7319`, `b784422`)_

- **Dataplane inspection.** `telepathy iptables|bpf|hns` render the actual
  iptables/nftables chains, annotated eBPF policy program, and Windows HNS ACL
  rules Felix would program for the same policy, without a cluster. _(`dda9d6c`, `bd9d353`)_

- **Windows / HNS support.** HNS ACL rendering plus confirmed Windows-specific
  policy divergences captured as e2e cases, with Linux expected-behaviour
  baselines to contrast against. _(`dda9d6c`, `dc555e8`, `a839ad6`, `5df0918`)_

- **CI/CD integration.** A GitHub Action wraps both gates: on every PR it runs
  your assertions and posts a sticky base-vs-PR connectivity diff as a comment.
  Ships as a single static binary in a `scratch` image, so any container CI
  (GitLab, Tekton, Argo, Jenkins) can call it the same way. _(`3c03ee2`, `ff2a07d`)_

- **Trust but Verify.** Telepathy now features two policy test modes: verify and e2e.
  verify runs a policy and topology, evaluating them against a user-created expectation.
  e2e runs the same workflow but compares the results against an actual live cluster.
  > Note: While all CNIs are supported by the e2e test, only Calico advanced policies are currently supported under the verify mode.

  _(`9f7ea02`, `d4d1bba`)_

- **Policy cost estimation.** Telepathy estimates a cost for each policy,
  how many rules it adds to iptables, or how many endpoints it selects and
  programs in an eBPF cluster, and e2e verifies the estimates against a live
  cluster. Cost is supported only for Calico and it supports four Calico dataplanes. _(`387899b`, `5b6010f`)_
  > **Note**: Policy cost estimation is a concept just to help visualize how a policy
  > can consume resources and it is inspired by the amazing CalicoCon [talk](https://www.youtube.com/watch?v=PA13_1IUCHE) from [@fasaxc](https://github.com/fasaxc).


## Testing & tooling

- End-to-end harness with per-engine testdata; a single command runs all e2e.
  E2E runs on releases only (it's costly); `make verify` / `make verify-all`
  are the fast PR/commit gates and now use the Go code rather than an old
  shell script.
- E2E no longer tries to delete the `default`, `kube-admin`, and
  `kube-baseline` tiers.
- Docker build/image and CI wiring.

## Project

- Apache-licensed with CNCF-aligned governance, license headers, and community
  docs (ADOPTERS, CODE_OF_CONDUCT, CONTRIBUTING, GOVERNANCE, SECURITY).

## Known limitations

- Antrea and Cilium engines support Kubernetes NetworkPolicy only.


## Release poem

Rumi #1759

There is nothing in all the universe that is not with you.

Seek within everything that you need is there.

```
بیرون ز تو نیست هرچه در عالم هست
در خود بطلب هر آنچه خواهی که توئی
```
