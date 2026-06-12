# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (`main`) | Yes |

Telepathy is pre-1.0. Only the latest commit on `main` receives security fixes.
Once versioned releases begin, the most recent minor release will be supported.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a vulnerability, email the maintainers via the follwoing form:

https://forms.gle/wBvVLUe9rUPXCE9JA

Include as much of the following as possible:

- Type of issue (e.g., arbitrary code execution, path traversal, denial of service)
- Full paths of source file(s) related to the issue
- Steps to reproduce
- Proof-of-concept or exploit code (if available)
- Impact assessment — what an attacker could achieve

You will receive an acknowledgement within **3 business days** and a more
detailed response within **7 business days** indicating next steps.

## Disclosure Process

1. The report is acknowledged and assessed by the maintainers.
2. A fix is developed in a private branch.
3. A patched release is prepared and staged.
4. The fix is released and a public advisory is published simultaneously.
5. The reporter is credited in the advisory unless they request otherwise.

We follow a **90-day disclosure timeline**: if a fix cannot be shipped within
90 days of the initial report, we will coordinate with the reporter on a
disclosure date.

## Scope

Telepathy is an **offline policy evaluator** — it reads files and writes to
stdout; it does not bind to any network port or access a Kubernetes cluster at
runtime. The primary attack surfaces are:

- Malformed or adversarially crafted topology/policy YAML fed to the engine
- The build toolchain (Makefile clones a pinned Calico tree)

Issues in the pinned Calico dependency should be reported to the
[Calico security team](https://github.com/projectcalico/calico/blob/master/SECURITY.md)
directly; we will update the pinned version in response to upstream advisories.
