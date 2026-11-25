<!--
The PR title becomes the squash-merge commit subject. Use the format
"<prefix>: <summary>", for example "jwt: reject tokens with an empty kid".
See CONTRIBUTING.md.

Security vulnerabilities must not be reported here. See SECURITY.md.
-->

## Why

<!-- What problem does this solve? Link the issue: Fixes #N -->

## What

<!-- Summary of the change and any trade-offs or alternatives considered. -->

## Checklist

- [ ] Tests cover the change (including rejection cases for security checks)
- [ ] `gofmt -l .`, `go vet ./...` and `go test -race ./...` pass
- [ ] No dependencies outside the standard library and `golang.org/x/*`
- [ ] `README.md` / `FEATURES.md` updated if public behavior changed
