# Roadmap

This document describes the planned direction for Telepathy. It is a living
document — priorities shift based on community feedback. Open an issue or join
a discussion if you want to influence what comes next.

Items marked **done** are shipped on `main`; everything else is planned.

---

## v0.1.0 — Foundation *(current target)*

Stabilise the existing feature set and establish the release infrastructure.

- [x] Connectivity matrix evaluation (`evaluate`)
- [x] Assertion-based CI gate (`test`)
- [x] Base-vs-PR connectivity diff (`diff`)
- [x] iptables/nftables chain rendering
- [x] eBPF policy program rendering
- [x] Windows HNS ACL rendering
- [x] GitHub Action wrapper
- [x] Apache 2.0 license
- [x] Governance, DCO, security policy
- [ ] Published `v0.1.0` release with attached static binary (linux/amd64, linux/arm64)
- [ ] Multi-arch Docker image pushed to GHCR

---

## v0.2.0 — Usability and coverage

Make the tool easier to adopt and cover more real-world policy patterns.

- [ ] **Namespace-scoped probes** — probe a subset of namespaces without
      specifying every endpoint
- [ ] **Service abstraction** — accept a `Service` object in the topology and
      resolve its selector to endpoints automatically
- [ ] **Policy linting** — surface common mistakes (shadow rules, unreachable
      allow, implicit deny on egress) as structured warnings
- [ ] **Human-readable text output** for `evaluate` (complement to JSON)
- [ ] **Topology auto-discovery** — optional flag to read live topology from a
      kubeconfig (cluster still not required for policy evaluation, only for
      populating the endpoint list)
- [ ] Improved error messages for malformed topology/policy YAML

---

## v0.3.0 — Pluggable backends *(vendor-neutrality milestone)*

Introduce a backend interface so the engine is not tied exclusively to
Calico/Felix. This is the prerequisite for CNCF sandbox consideration.

- [ ] **Backend interface** — define a minimal `PolicyBackend` interface
      (`Evaluate(topology, policies) → matrix`) that different CNI
      implementations can satisfy
- [ ] **Calico backend** — move the current Felix-based implementation behind
      the interface (no behaviour change for existing users)
- [ ] **Vanilla `networking.k8s.io/v1` backend** — a pure-Go implementation
      of standard Kubernetes NetworkPolicy semantics, with no CNI dependency,
      for clusters that don't run Calico
- [ ] Backend selection via `-backend calico|k8s|auto` flag (`auto` infers
      from the policy manifests present)
- [ ] Backend documentation and example for third-party implementors

---

## v0.4.0 — Ecosystem integrations

Broaden CI/CD reach beyond GitHub Actions.

- [ ] **GitLab CI component**
- [ ] **Tekton Task**
- [ ] **Argo Workflows template**
- [ ] **VS Code extension** — inline policy evaluation on save
- [ ] Server mode (`calico-engine serve`) — long-running HTTP/gRPC endpoint
      for editors and policy managers that want to avoid per-call fork/exec

---

## v1.0.0 — Stable API

Commit to a stable engine API and CLI contract.

- [ ] Stable `engine` package API with a documented compatibility guarantee
- [ ] Stable Request/Response JSON schema (versioned)
- [ ] End-to-end conformance test suite
- [ ] CNCF sandbox application

---

## Ideas under consideration

These are not yet scheduled. Open an issue if any of these matter to you.

- Cilium `CiliumNetworkPolicy` backend
- Antrea `ClusterNetworkPolicy` backend
- Policy mutation suggestions ("to allow this flow, add rule X")
- Interactive REPL mode
- Web UI for local policy exploration
