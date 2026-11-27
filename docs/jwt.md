# JWT

[← authent README](../README.md)

```go
signer, _ := jwt.NewSigner(jwt.ES256, privKey, jwt.WithKeyID("2026-01"))
token, _ := signer.Sign(jwt.Claims{Issuer: iss, Subject: "u1", Audience: jwt.Audience{"api"},
	ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute))})

keys, _ := jwt.NewRemoteKeySet("https://auth.example/.well-known/jwks.json")
verifier, _ := jwt.NewVerifier(keys,
	jwt.WithAlgorithms(jwt.ES256),       // required
	jwt.WithIssuer(iss),                 // WithIssuer or WithAnyIssuer is required
	jwt.WithAudience("api"),             // WithAudience or WithAnyAudience is required
	jwt.WithLeeway(30*time.Second))
p, err := verifier.Authenticate(ctx, token)
```

Safeguards enforced during verification:
- **Algorithms**
  - `alg` must be on an explicit allow-list, and `none` is always rejected.
  - A key is only used with an algorithm that matches its type, which
    prevents algorithm-confusion attacks. If a JWK has an `alg`, the key is
    restricted to that algorithm.
- **Claims and headers**
  - `exp` is required, unless `jwt.WithOptionalExpiration()` is set for a
    JWT that is consumed on arrival, such as a signed UserInfo response.
  - Tokens with a `cnf` claim (sender-constrained, e.g. DPoP-bound) are
    rejected unless `jwt.WithConfirmationClaim()` is set, so a stolen bound
    token cannot be replayed as a bearer token (RFC 9449 §7.2).
  - Headers with `crit`, `b64` or `zip` are rejected.
  - `jku`, `x5u`, `x5c` and `jwk` headers are never used to find keys.
- **Encoding**
  - JSON is decoded with `encoding/json/v2`: member names are matched
    case-sensitively and duplicate members are rejected.
  - Non-canonical base64url is rejected. This covers line breaks, padding
    and non-zero trailing bits.
- **Signatures and keys**
  - ECDSA signatures must use the fixed-width R‖S form.
  - RSA keys must be at least 2048 bits.
  - HMAC keys must be at least as long as the hash output.

Optional checks:
- `jwt.WithReplayCache(jwt.NewMemoryReplayCache())` accepts each token
  once. `jti` becomes required, and the `iss` and `jti` pair is recorded
  until `exp` once every other check has passed. A cache error rejects the
  token but does not wrap `authent.ErrUnauthenticated`. `dpop.Verifier`
  takes the same `jwt.ReplayCache` interface. Use it for single-use
  tokens (ID tokens, logout tokens, client assertions, request objects),
  not for access tokens, which clients send many times.
- Behind a load balancer, share one cache between servers.
  `sqlreplay.New(db, sqlreplay.PostgreSQL)` from `jwt/sqlreplay` stores
  entries in PostgreSQL or SQLite through `database/sql`, with no driver
  import. `CreateTable` (or `CreateTableStatements` for a migration tool)
  creates the table. `Add` is one `INSERT ... ON CONFLICT DO UPDATE ...
  WHERE` statement, so concurrent servers agree on which one saw an id
  first, and an expired row is taken over. Call `DeleteExpired`
  periodically. MySQL is not supported, because its affected-row count
  cannot tell an unchanged duplicate from an update when
  `CLIENT_FOUND_ROWS` is set. For Redis, `redisreplay.New(client)` from
  the `github.com/tohshi/authent/redis` module records each id with
  `SET NX` and an expiry, so Redis drops expired entries itself. It takes
  any `redis.UniversalClient`, including Redis Cluster. `replaytest.TestReplayCache` (in
  `jwt/replaytest`) is a conformance suite for your own `jwt.ReplayCache`.
- `jwt.WithMaxTokenAge(d)` rejects tokens issued more than `d` ago and
  makes `iat` required. `jwt.WithMaxAuthAge(d)` does the same for
  `auth_time`, as OpenID Connect `max_age` requires, and rejects an
  `auth_time` in the future. Both allow the leeway on top of `d`. `Claims.AuthTime` reads `auth_time` for
  per-request checks.
- `jwt.WithCertificateRoots(pool)` only uses JWKs whose `x5c` chain
  verifies to `pool` at the verifier's clock, with a leaf allowed to make
  digital signatures. Keys without `x5c` are not used. Independently of
  this option, a JWK whose `x5c` leaf certifies a different key is
  rejected when parsed, and a JWK built in code with such a chain is not
  used under `WithCertificateRoots`.

A signing key can come from a private JWK:
```go
k, _ := jwt.ParsePrivateJWK(data) // RSA with CRT values, EC or Ed25519; checked against the public members
signer, _ := jwt.NewSigner(jwt.ES256, k.Key, jwt.WithKeyID(k.KeyID))
```
`ParseJWK` rejects any JWK with private members, and `ParseJWKSet` drops
such keys, so a leaked private key is never used to verify tokens.

`RemoteKeySet` keeps a fetched set for the `max-age` of its
`Cache-Control` header, clamped between `WithMinRefreshInterval` (default
1 minute) and `WithMaxRefreshInterval` (default 24 hours). `no-store` and
`no-cache` keep it for the minimum interval. Without `max-age`,
`WithRefreshInterval` (default 1 hour) applies. A token with an unknown
`kid` triggers an early refetch, at most once per minimum interval.
