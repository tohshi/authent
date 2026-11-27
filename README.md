# authent

[![CI](https://github.com/tohshi/authent/actions/workflows/ci.yml/badge.svg)](https://github.com/tohshi/authent/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/tohshi/authent.svg)](https://pkg.go.dev/github.com/tohshi/authent)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Authentication and authorization building blocks for Go. Use the packages
individually with any HTTP framework, or without HTTP. The root module depends
only on the Go standard library and `golang.org/x` modules.

```sh
go get github.com/tohshi/authent
```

## Quick start

Hash and verify a password with Argon2id:

```go
package main

import (
	"log"

	"github.com/tohshi/authent/password"
)

func main() {
	hasher, err := password.NewHasher(password.DefaultParams)
	if err != nil {
		log.Fatal(err)
	}
	hash, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		log.Fatal(err)
	}
	if err := hasher.Verify("correct horse battery staple", hash); err != nil {
		log.Fatal(err)
	}
}
```

For a login flow with credential storage, password policy and hash upgrades,
see the [password guide](docs/passwords.md). Other packages have separate
guides below.

## Packages and guides

| Package | Purpose | Guide |
|---|---|---|
| `authent` | Shared `Principal`, `Observer` and `ErrUnauthenticated` | [Core API](https://pkg.go.dev/github.com/tohshi/authent) |
| `password` | Argon2id hashing, password policy, login and resets | [Passwords](docs/passwords.md) |
| `jwt` | JWT signing and verification, JWK/JWKS and key rotation | [JWT](docs/jwt.md) |
| `session` | Server-side sessions, expiry, rotation and CSRF tokens | [Sessions](docs/sessions.md) |
| `apikey` | Hashed API keys with expiry and revocation | [API keys](docs/api-keys.md) |
| `oidc` | OpenID Connect relying party with PKCE, PAR, JAR and logout | [OIDC](docs/oidc.md) |
| `dpop` | DPoP proofs, client transport and resource server verification | [DPoP](docs/dpop.md) |
| `totp` | One-time passwords and replay protection | [TOTP](docs/totp.md) |
| `webauthn` | Passkeys and security keys | [WebAuthn](docs/webauthn.md) |
| `httpauth` | `net/http` middleware for JWTs, sessions and API keys | [HTTP middleware](docs/http-middleware.md) |
| `rebac` | Relationship-based access control | [ReBAC](docs/rebac.md) |

For logging, metrics and tracing across packages, see
[observability](docs/observability.md).

Authentication methods return an `authent.Principal`. Authentication failures
wrap `authent.ErrUnauthenticated`, which callers can detect with `errors.Is`.
Store and network errors do not wrap it, so callers can distinguish rejected
credentials from server failures.

See [FEATURES.md](FEATURES.md) for the complete feature status and deliberate
scope exclusions. See [Go Reference](https://pkg.go.dev/github.com/tohshi/authent)
for the API.

## Testing

```sh
go test -race ./...
scripts/fuzz.sh # every fuzz target; set FUZZTIME to change the default 15s
```

The tests include independent RFC, OpenSSL, WebAuthn and py_webauthn vectors.
See [test vectors](docs/testing.md) for their sources and
[CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
