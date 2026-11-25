# Contributing to authent

Thanks for your interest in improving authent. This is a security-sensitive
library, so changes are reviewed with correctness and safety first.

> **Found a vulnerability?** Do not open a public issue or pull request.
> Follow [SECURITY.md](SECURITY.md) instead.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree
  on the approach before you spend time on it.
- Check [FEATURES.md](FEATURES.md). Items listed as out of scope are unlikely
  to be accepted.

## Ground rules

- **Dependencies.** Only the Go standard library and `golang.org/x/*` modules
  are allowed. Pull requests that add any other module to `go.mod` will not
  be merged. Cryptographic formats such as JWS and JWK are implemented here on
  top of `crypto/*`.
- **Fail closed.** When in doubt, reject. Ambiguous input, unknown parameters
  and store errors must never result in a successful authentication or a
  granted permission.
- **Errors.** Authentication failures wrap `authent.ErrUnauthenticated`.
  Infrastructure failures (store, network) must not.
- **Tests.** Every behavior change needs a test. Security checks need a test
  that proves the bad input is rejected. Prefer RFC test vectors or vectors
  from an independent implementation where they exist.
- **Docs.** Update `README.md` and `FEATURES.md` when you change public
  behavior. All code, comments and docs are written in English.

## Development

Requires the Go version declared in `go.mod`.

```
gofmt -l .                # must print nothing
go vet ./...
go test -race ./...
go test ./jwt -run '^$' -fuzz FuzzVerify -fuzztime 30s
go test ./webauthn -run '^$' -fuzz FuzzCBOR -fuzztime 30s
go test ./webauthn -run '^$' -fuzz FuzzParseAuthData -fuzztime 30s
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

CI runs the same checks on every pull request.

## Commit messages

We follow the [Go project's convention](https://go.dev/wiki/CommitMessage).

```
jwt: reject tokens whose kid header is empty

An empty kid matched every key in a JWKS that had no kid, which let a
token be verified against an unintended key when the set contained
keys for several algorithms.

Fixes #42
```

- **First line:** `<prefix>: <summary>`
  - The prefix is the package directory you changed (`jwt`, `oidc`,
    `password`, `rebac`, `session`, `totp`, `webauthn`, or `authent` for
    the root package).
    Use a comma-separated list for a few packages (`jwt, oidc: ...`) and
    `all:` for repository-wide changes. For non-code changes use the file
    or directory (`README:`, `.github:`, `CONTRIBUTING:`).
  - The summary is lowercase, written so that it completes the sentence
    "This change modifies authent to ___", and has no trailing period.
  - Keep the whole line under about 72 characters.
- **Body:** separated by a blank line and wrapped at 72 columns. Explain
  *why* the change is needed and what the trade-offs are. The diff already
  shows *what* changed.
- **References:** put `Fixes #N` or `Updates #N` on their own line at the end.

To get the template in your editor:

```
git config commit.template .gitmessage
```

## Pull requests

- Keep each pull request focused on one change.
- Pull requests are squash-merged, so the PR title and description become
  the commit message. Write them in the format above.
- Make sure CI is green before requesting review.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
