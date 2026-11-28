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

- **Dependencies.** Direct requirements in the root module are limited to
  `golang.org/x/*`; CI checks that compiled dependencies follow this policy.
  SQL adapters use `database/sql` without a driver; the separate `redis/`
  module alone depends on `go-redis`. Pull requests that add another direct
  requirement to the root `go.mod` will not be merged.
  Cryptographic formats such as JWS and JWK are implemented here on top of
  `crypto/*`.
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
- **Release notes.** For a user-facing change, add a Changie fragment with a
  short description of its effect. Internal-only changes do not need one.

## Development

Requires the Go version declared in `go.mod`.

```
gofmt -l .                # must print nothing
go vet ./...
go test -race ./...
scripts/fuzz.sh           # every fuzz target, FUZZTIME each (default 15s)
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Adapters for external services (PostgreSQL, Redis) are tested from nested
modules such as `integration/`, so their drivers stay out of the root
module. These tests skip when their service is not configured. To run them:

```
docker run -d --name authent-pg -e POSTGRES_PASSWORD=authent -e POSTGRES_DB=authent -p 55432:5432 postgres:17
docker run -d --name authent-redis -p 56379:6379 redis:8
export AUTHENT_POSTGRES_DSN='postgres://postgres:authent@localhost:55432/authent?sslmode=disable'
export AUTHENT_REDIS_ADDR=localhost:56379
export AUTHENT_REQUIRE_INTEGRATION=1   # fail instead of skip when a service is missing
(cd integration && go test -race ./...)
```

CI runs the same checks on every pull request, with
`AUTHENT_REQUIRE_INTEGRATION=1`.

## Releasing the Redis module

`redis/` is a separate Go module. Its `require github.com/tohshi/authent`
must name a resolvable core version that contains the store interfaces it
uses. The local `replace github.com/tohshi/authent => ../` is for development;
Go ignores it when another module imports the Redis module. Before releasing
the Redis module, update that requirement to the intended core tag or commit,
run `go mod tidy` in `redis/`, then run
`bash .github/scripts/check-redis-consumer.sh` from the repository root. The
check builds both Redis adapters from a fresh consumer module without a core
`replace`. A release tag for this nested module must start with `redis/`, for
example `redis/v0.1.0`; a root-module tag does not release it.

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
  - The prefix is the package directory you changed (`jwt`, `oidc`, `dpop`,
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
- For user-facing changes, install Changie with
  `go install github.com/miniscruff/changie@v1.26.0` and run `changie new`.
  Choose Added, Changed, Fixed, or Security. Commit the generated file in
  `.changes/unreleased/` with the PR. Release versions are chosen separately
  by the maintainer; the fragment does not need a version number.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
