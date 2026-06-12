# Contributing to Telepathy

Thank you for your interest in contributing. This document covers everything
you need to get from zero to a merged pull request.

## Before you start

- Check [open issues](https://github.com/frozenprocess/telepathy/issues) to see
  if the work is already in progress.
- For significant changes (new features, breaking API changes, changes to
  governance), open a `proposal` issue first and allow two weeks for discussion
  before writing code.
- All contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Developer Certificate of Origin (DCO)

Every commit must be signed off to certify that you wrote the code and have the
right to contribute it under the Apache 2.0 license. Add a `Signed-off-by`
line to your commit message:

```
Signed-off-by: Your Name <your@email.com>
```

The easiest way is `git commit -s`. CI will reject PRs that contain unsigned
commits.

## Development setup

**Requirements:** Git, Go (version in [`.go-version`](.go-version)), Docker
(only for `make image` / `make build-docker`).

```bash
# Clone the repo
git clone https://github.com/frozenprocess/telepathy.git
cd telepathy

# Build the engine (clones the pinned Calico tree on first run)
make build

# Run the unit tests
go test ./engine/...

# Run the sample assertion gate
make verify

# Run the connectivity diff demo
make diff-demo
```

`make help` lists all available targets.

### How the build works

The engine imports Calico directly from a pinned source tree cloned into
`third_party/calico`. `make build` clones that tree (once) and wires it to the
engine module via a `go.work` workspace. You never need to touch the Calico
checkout. `make distclean` removes it entirely for a fresh start.

The engine is Linux-only (it uses Linux-specific Calico/Felix internals). On
macOS or Windows, use `make build-docker` to build inside a container, or run
the tests via `make image` + Docker.

## Making changes

1. Fork the repository and create a branch off `main`.
2. Write your code. Keep commits focused and their messages descriptive.
3. Add or update tests for any behaviour change.
4. Ensure CI passes locally before pushing:

   ```bash
   go test ./engine/...
   make verify
   make diff-demo
   ```

5. Open a pull request against `main`. Fill in the PR description — what the
   change does and why.
6. Respond to review comments. A maintainer will merge once approved and CI is
   green.

## Commit message style

```
Short summary in the imperative (max 72 chars)

Optional longer explanation of why this change is needed.
Reference issues with "Fixes #123" or "Related to #456".

Signed-off-by: Your Name <your@email.com>
```

## Adding a new policy type or dataplane

The engine lives in [`engine/`](engine/). The entry points are:

| File | What it owns |
|------|-------------|
| `eval.go` | `Evaluate` — pod-to-pod connectivity matrix |
| `iptables.go` | `RenderIptables` — iptables/nftables chain rendering |
| `bpf.go` | `RenderBPF` — eBPF program rendering |
| `hns.go` | `RenderHNS` — Windows HNS ACL rendering |
| `load.go` | Request decoding and policy manifest parsing |
| `types.go` | Shared types (Request, Response, etc.) |

New subcommands belong in `main.go`; new engine capabilities belong in a new
file under `engine/` with a corresponding test file.

## Reporting bugs

Open a [GitHub issue](https://github.com/frozenprocess/telepathy/issues) with:

- The `calico-engine version` output
- The topology and policy YAML that triggers the bug (redact anything sensitive)
- The observed output and what you expected instead

For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do not use
public issues.
