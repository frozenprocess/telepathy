# Telepathy Governance

## Overview

Telepathy is an open-source project. This document describes how the project is
governed and how decisions are made.

## Roles

### Users

Anyone who uses Telepathy. Users are encouraged to participate in the community
by filing issues, opening pull requests, and joining discussions.

### Contributors

Anyone who has submitted a pull request that was merged. Contributors are
expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md) and to sign off
commits with a [Developer Certificate of Origin](#developer-certificate-of-origin).

### Maintainers

Maintainers have write access to the repository. They review and merge pull
requests, triage issues, and guide the technical direction of the project.

Current maintainers:

| Name | GitHub | Affiliation |
|------|--------|-------------|
| Reza Ramezanpour | [@frozenprocess](https://github.com/frozenprocess) | Project Calico |

Maintainers are listed in [CODEOWNERS](CODEOWNERS).

### Becoming a Maintainer

A contributor may be nominated as a maintainer by any existing maintainer. To
be considered, a candidate should have:

- Merged contributions over a sustained period (typically 3+ months)
- Demonstrated good judgment in code review and issue triage
- Shown commitment to the project's goals and community

Nominations are decided by a simple majority vote among existing maintainers,
conducted as a GitHub issue with a two-week comment period. The nominee must
accept before the role is confirmed.

### Removing a Maintainer

A maintainer may step down voluntarily at any time by opening a PR removing
themselves from CODEOWNERS. A maintainer who has been inactive for six months
may be moved to Emeritus status by a vote of the remaining maintainers.

## Decision Making

The project uses a **lazy consensus** model: a change may proceed if no
maintainer objects within a reasonable window (typically five business days for
non-trivial changes). If consensus cannot be reached, a simple majority vote
among maintainers decides.

For significant changes — new features, breaking API changes, changes to
governance — a GitHub issue marked `proposal` must be opened for community
discussion before any implementation begins. A two-week comment period is
required before a decision is made.

## Pull Request Process

1. Fork the repository and open a pull request against `main`.
2. All commits must be signed off (see [DCO](#developer-certificate-of-origin)).
3. At least one maintainer approval is required before merging.
4. CI must pass before merging.
5. The author should resolve review comments; a maintainer may merge after
   seven days if the author is unresponsive and the change is otherwise ready.

## Developer Certificate of Origin

All contributions must be signed off with the
[Developer Certificate of Origin (DCO)](https://developercertificate.org/).
This is done by adding a `Signed-off-by` line to each commit message:

```
Signed-off-by: Your Name <your@email.com>
```

Use `git commit -s` to add this automatically. DCO compliance is enforced by
CI on every pull request.

## Code of Conduct

This project follows the
[CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).
Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported by opening a GitHub issue or by contacting a maintainer directly.

## Amendments

Changes to this document require a two-week comment period and a majority vote
of maintainers.
