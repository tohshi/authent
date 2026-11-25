# Security Policy

authent implements authentication and authorization primitives, so we take
security reports seriously and appreciate responsible disclosure.

## Supported versions

authent has not reached v1 yet. Only the latest release and the `main`
branch receive security fixes.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues,
discussions or pull requests.**

Report them privately through GitHub:

1. Go to the [Security tab](https://github.com/tohshi/authent/security) of
   this repository.
2. Click **Report a vulnerability**.

Please include:

- the affected package and version (or commit)
- a description of the issue and its impact
- steps to reproduce, ideally a minimal Go test or token that triggers it

## What to expect

- We aim to acknowledge reports within 5 business days.
- We will keep you informed while we investigate and prepare a fix.
- Once a fix is released, we will publish a GitHub Security Advisory and
  credit you unless you prefer to stay anonymous.

## Scope

Examples of issues we consider vulnerabilities:

- a token, session, password or OIDC response that is accepted when it
  should be rejected
- algorithm confusion, signature bypass or key selection flaws in `jwt`
- timing side channels that reveal secrets or account existence
- a ReBAC check that grants access it should deny, including on errors
- denial of service through crafted input with disproportionate cost

Misuse of the API that the documentation warns against, and vulnerabilities
in the Go toolchain or `golang.org/x/*` modules themselves, are out of scope.
Please report the latter to the [Go security team](https://go.dev/security/policy).
