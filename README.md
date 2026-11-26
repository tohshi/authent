# authent

[![CI](https://github.com/tohshi/authent/actions/workflows/ci.yml/badge.svg)](https://github.com/tohshi/authent/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/tohshi/authent.svg)](https://pkg.go.dev/github.com/tohshi/authent)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Authentication (authn) and authorization (authz) building blocks for Go,
independent of any HTTP framework. The only dependencies are the Go standard
library, `golang.org/x/crypto` and `golang.org/x/oauth2`.

```
go get github.com/tohshi/authent
```

## Packages

| Package | Purpose |
|---|---|
| `authent` | The shared `Principal` (an authenticated subject) and `ErrUnauthenticated` |
| `password` | Argon2id password hashing and verification, new-password policy, `Authenticator` |
| `jwt` | JWS/JWT signing and verification, JWK/JWKS, `RemoteKeySet` with caching and key rotation |
| `session` | Server-side sessions with idle and absolute timeouts, ID rotation and CSRF tokens |
| `oidc` | OpenID Connect relying party (authorization code flow with PKCE S256, PAR, JAR, DPoP, refresh, logout) |
| `dpop` | DPoP (RFC 9449): client proofs and transport, resource server verification |
| `totp` | Time-based one-time passwords (RFC 6238) with replay protection |
| `webauthn` | WebAuthn relying party: passkeys and security keys |
| `rebac` | Zanzibar-style relationship-based access control (ReBAC) |
| `apikey` | API keys with a scannable prefix and checksum, stored hashed |
| `httpauth` | `net/http` middleware: bearer JWTs, session cookies with CSRF checks, API keys |

Every authentication method returns an `authent.Principal`. Every
authentication failure wraps `authent.ErrUnauthenticated`, so callers can
detect all of them with a single `errors.Is(err, authent.ErrUnauthenticated)`.
Store failures and network errors do not wrap it. This lets you tell
"authentication failed" (401) apart from "the server failed" (5xx).

## Usage

### Passwords
```go
hasher, _ := password.NewHasher(password.DefaultParams) // RFC 9106 recommendation
auth, _ := password.NewAuthenticator(store, hasher)       // store implements CredentialStore
p, err := auth.Authenticate(ctx, username, pw)
```
- When setting or changing a password, use the policy to validate and hash it:
  ```go
  checker := password.NewPwnedPasswordsChecker(nil) // 5-second HTTP timeout
  blocked, _ := password.NewStaticBlocklist("authent-password-2026")
  policy, _ := password.NewPolicy(password.DefaultMinLength, password.DefaultMaxLength,
      checker, password.WithBlocklist(blocked))
  hash, err := policy.Hash(ctx, hasher, newPassword)
  ```
  `Policy.Hash` checks the password before hashing. It can return `ErrTooShort`,
  `ErrTooLong`, `ErrBlocked`, `ErrBreached`, or a lookup error. The default
  limits are 15–1024 Unicode code points. The optional blocklist matches
  entire passwords, including service- or account-specific values supplied by
  the caller. Passwords are normalized to NFC before checking and hashing;
  hashes carry an NFC marker. Legacy hashes keep their original byte semantics.
  The breach lookup sends
  only the first five SHA-1 hex digits to the Pwned Passwords API over HTTPS,
  with response padding requested. Service failures reject the check; they do
  not silently accept the password. The policy is not applied during login or
  hash upgrades, so existing passwords continue to work. `Hasher.Hash` remains
  available for existing callers but does not apply the policy.
  No character-class or periodic-rotation rules are imposed, following
  [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html#passwords).
- Unknown users are checked against a dummy hash, so response times do not
  reveal whether a username exists.
- If `store` also implements `CredentialUpdater`, hashes created with
  outdated parameters are upgraded after a successful login.
- A pepper is a server-side secret that a stolen credential database does
  not contain. Keep it in a secret manager, not next to the hashes:
  ```go
  hasher, _ := password.NewHasher(password.DefaultParams,
      password.WithPepper("2026", pepper),           // at least 32 bytes
      password.WithRetiredPepper("2025", oldPepper)) // verify only
  ```
  The password is normalized (for NFC-tagged hashes), keyed with
  HMAC-SHA-256 under the pepper, then hashed with Argon2id. The hash records
  the key ID as `keyid=2026`. Hashes with a retired pepper or no pepper still
  verify and report `NeedsRehash`, so logins move them to the current pepper.
  A hash whose key ID is not configured fails with `ErrUnknownPepper`, which
  `Authenticate` returns as a server error rather than a login failure.
- Password reset tokens are single use and expire after 30 minutes by
  default:
  ```go
  resets, _ := password.NewResetManager(password.NewMemoryResetStore())
  token, err := resets.Issue(ctx, subject) // send it to the user, e.g. in a link
  subject, err := resets.Redeem(ctx, token) // then set the new password with policy.Hash
  ```
  The store keeps only the token's SHA-256 hash, the subject and the expiry.
  `ResetTokenStore.TakeResetToken` must remove and return a token in one
  atomic step (in SQL, `DELETE ... RETURNING` or a locking transaction), so
  a token cannot be redeemed twice. Issuing a token invalidates the
  subject's earlier ones, so only the most recent link works. Expired,
  unknown and reused tokens return `ErrInvalidResetToken`, which wraps
  `authent.ErrUnauthenticated`.
- To migrate users from another system, store their existing hashes as they
  are. `Verify` accepts bcrypt (`$2a$`, `$2b$`, `$2y$`), Werkzeug scrypt
  (`scrypt:32768:8:1$salt$hex`, the Flask default) and Django PBKDF2
  (`pbkdf2_sha256$1000000$salt$base64`, the Django default). It never creates
  them. `NeedsRehash` always reports them, so `Authenticate` replaces each one
  with Argon2id at the user's next login. They are compared byte for byte,
  without NFC normalization, as the original system did. Hashes above bcrypt
  cost 16, 256 MiB of scrypt memory or 10,000,000 PBKDF2 iterations are
  rejected as malformed.

### JWT
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

### Sessions
```go
m, _ := session.NewManager(store, session.WithIdleTimeout(30*time.Minute), session.WithAbsoluteTimeout(24*time.Hour))
token, s, _ := m.Create(ctx, p)        // create a new session on every login (prevents session fixation)
s, err := m.Get(ctx, token)            // expired or invalid tokens return ErrInvalidSession
s.VerifyCSRF(formToken)                // check on state-changing requests
newToken, s, _ := m.Rotate(ctx, token) // issue a new ID when privileges change
m.Destroy(ctx, token)                  // log out
```
The store is keyed by the SHA-256 hash of the token, so raw tokens are never
stored. Setting cookie attributes (`Secure`, `HttpOnly`, `SameSite`) is up to
the caller.

Application data is stored as JSON under typed keys:
```go
var cartKey = session.Key[Cart]("cart")
err := cartKey.Set(s, cart) // then m.Save(ctx, s)
cart, ok, err := cartKey.Get(s)
```
A stored value that no longer decodes into the key's type is an error, not
a zero value.

A session records each authentication factor with its time. Require a
second factor, or a recent authentication, before sensitive actions:
```go
if !s.AuthenticatedSince(time.Now().Add(-10*time.Minute), authent.MethodTOTP) {
	// ask for a TOTP code, verify it with totp.Authenticator, then:
	token, s, err = m.StepUp(ctx, token, p) // p is the TOTP Principal
}
```
`StepUp` rejects a Principal whose subject or issuer differs from the
session's, and rotates the token like `Rotate`. Factors change only
through `Create` and `StepUp`. `Session.Principal` reports the methods in
the `amr` claim and the most recent authentication as `AuthTime`.

Stores index sessions by subject, so a subject's sessions can be listed
and revoked:
```go
list, err := m.List(ctx, s.Subject())  // for an account page; no tokens or CSRF tokens
err = m.Revoke(ctx, s.Subject(), handle) // handle from Session.Handle()
err = m.RevokeAll(ctx, s.Subject())      // log out everywhere
```
`Revoke` ends a session only if it belongs to the given subject, so pass
the subject of the session making the request. A session that is rotated
or stepped up while `RevokeAll` runs does not survive under its new token.

#### Persistent session storage
```go
import _ "github.com/jackc/pgx/v5/stdlib" // or any database/sql driver

db, _ := sql.Open("pgx", dsn)
store, _ := session.NewSQLStore(db, session.PostgreSQL) // also session.MySQL, session.SQLite
store.CreateTable(ctx) // or apply store.CreateTableStatements() with your migration tool
m, _ := session.NewManager(store)
// periodically: store.DeleteExpired(ctx)
```
- `SQLStore` works through `database/sql` and imports no driver; you
  choose one.
- Each session is one row keyed by the token hash, with an expiry column.
  `Load` and `List` ignore expired rows, and `DeleteExpired` removes them.
  The Manager still enforces the timeouts itself.
- Every operation is a single statement, and versions are compared in its
  `WHERE` clause, so concurrent saves are detected without transactions.
- Token hashes and subjects are compared byte by byte (`COLLATE "C"` on
  PostgreSQL, `VARBINARY` on MySQL). Subjects may be up to 1024 bytes.

For Redis, use the separate `github.com/tohshi/authent/redis` module, which
keeps the go-redis dependency out of the core module:
```go
import "github.com/tohshi/authent/redis/redissession"

store, _ := redissession.New(redis.NewClient(&redis.Options{Addr: addr}))
m, _ := session.NewManager(store)
```
- Each session is a hash with a TTL, set relative to the application's
  clock. A sorted set per subject indexes the sessions and expires with
  the last of them, so nothing needs periodic cleanup.
- Lua scripts make the version check and `DeleteSubject` atomic.
- Redis Cluster is not supported, because the scripts touch keys in
  several slots.

Every stored session has a version, and stores save it with a
compare-and-swap. `Save` returns an error wrapping `session.ErrConflict`
when another request saved, rotated or destroyed the session after it was
loaded; get it again and reapply the change. `ErrConflict` does not wrap
`authent.ErrUnauthenticated`. `sessiontest.TestStore` is a conformance
suite for `Store` implementations.

### API keys
```go
keys, _ := apikey.NewManager("myapp", store) // store implements apikey.Store; or apikey.NewMemoryStore()
key, rec, _ := keys.Create(ctx, "u1", time.Now().AddDate(1, 0, 0)) // show key once; rec.ID is public
p, err := keys.Authenticate(ctx, key) // p.Method is authent.MethodAPIKey, p.Claims["key_id"] is rec.ID
keys.Revoke(ctx, rec.ID)
```
- Keys look like `myapp_<id>_<secret>`. A fixed prefix and format let
  secret scanners find leaked keys.
- The last segment carries a CRC-32 of the whole key. Mistyped or
  truncated keys fail with `apikey.ErrMalformed` before the store is
  queried.
- The store keeps the SHA-256 of the secret, never the key itself. Hashes
  are compared in constant time.
- Every key has an expiry. Unknown, wrong, expired and revoked keys wrap
  `authent.ErrUnauthenticated`; store failures do not.

### OIDC
```go
prov, _ := oidc.Discover(ctx, "https://accounts.example.com", nil)
client, _ := oidc.NewClient(prov, oidc.Config{ClientID: id, ClientSecret: secret, RedirectURL: cb})

req, _ := client.AuthCodeURL() // store all of req server-side, bound to the browser
// ... redirect to req.URL and receive the callback ...
res, err := client.Exchange(ctx, req, r.URL.Query().Get("state"), r.URL.Query().Get("code"))

info, err := client.UserInfo(ctx, res.Token, res.Principal.Subject) // optional
```
For `private_key_jwt`, register the corresponding public key with the provider
and configure an asymmetric signing key instead of `ClientSecret`:
```go
client, _ := oidc.NewClient(prov, oidc.Config{
	ClientID: id, RedirectURL: cb,
	PrivateKeyJWT: &oidc.PrivateKeyJWTConfig{
		Algorithm: jwt.ES256, PrivateKey: privateKey, KeyID: "client-key-1",
	},
})
```
Each token exchange signs a fresh, five-minute client assertion. Its audience
is the provider issuer, as required by RFC 10070.

`Exchange` checks:
- the state and nonce
- PKCE (S256)
- the ID token's signature, `iss`, `aud` and `exp`
- `azp`
- `at_hash`
- `auth_time` and `acr`, when the request asked for them:
```go
req, _ := client.AuthCodeURL(
	oauth2.SetAuthURLParam("max_age", "300"),
	oauth2.SetAuthURLParam("acr_values", "urn:example:mfa"))
```
  With `max_age`, the ID token must carry an `auth_time` at most that many
  seconds old, plus `Config.Leeway`, so `max_age=0` still accepts an
  authentication within the leeway. With `acr_values`, its `acr` must be
  one of the requested values, as for an essential claim. Both are kept in
  the `AuthRequest`, so store all of it: `Exchange` fails rather than skip
  the checks if `MaxAge` or `ACRValues` are lost.

`UserInfo` calls the provider's UserInfo endpoint with the access token and
rejects the response unless its `sub` exactly matches the ID token's. A
signed response (`application/jwt`) must also verify with the provider's
keys and carry the provider as `iss` and the client in `aud`; it needs no
`exp`. With `Config.RequireSignedUserInfo`, plain JSON responses are
rejected. Encrypted responses are always rejected. Redirects are not followed, so the
access token is never sent anywhere but the advertised https endpoint.

`Refresh` uses a `Result`'s refresh token and returns the next `Result`:
```go
res, err = client.Refresh(ctx, res) // store res again: the refresh token may have rotated
```
It authenticates the client as `Exchange` does, including with
`private_key_jwt`, and sends DPoP proofs when configured. A new ID token
must verify like the first one and describe the same authentication: the
same `iss`, `sub`, `aud` and `azp`, and the same `auth_time` and `nonce`
when it has them. A rejected refresh token wraps `oidc.ErrRefreshRejected`.

Logout works in both directions:
```go
// RP-initiated: end the local session, then log out at the provider.
u, _ := client.EndSessionURL(oidc.EndSession{
	IDTokenHint: res.RawIDToken, PostLogoutRedirectURI: "https://app.example/bye", State: state,
})

// Front-channel: GET on the frontchannel_logout_uri.
l, err := client.FrontChannelLogout(r.URL.Query())

// Back-channel: POST on the backchannel_logout_uri.
r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
	// reply 400
}
l, err := client.BackChannelLogout(ctx, r.PostFormValue("logout_token"))
// end every local session whose ID token l.Matches; reply 200, or 400 on error
```
- Front-channel requests must carry the provider's `iss` and a `sid`, so
  register the client with `frontchannel_logout_session_required`.
- Logout tokens are verified like ID tokens. They must also be typed
  `logout+jwt`, carry the back-channel logout event and a `sub` or `sid`,
  have no `nonce`, and be at most two minutes old. Each `jti` is accepted
  once through `Config.ReplayCache` (in memory by default; use a shared
  cache such as `jwt/sqlreplay` behind a load balancer).
- Respond to both with `Cache-Control: no-store`.

Pushed authorization requests (RFC 9126) send the parameters to the
provider over the back channel, so the browser only sees a `request_uri`:
```go
req, err := client.PushAuthCodeURL(ctx) // redirect to req.URL before req.Expiry
```
`AuthCodeURL` returns `oidc.ErrPARRequired` when the provider sets
`require_pushed_authorization_requests`. The client authenticates at the PAR
endpoint as at the token endpoint, with its secret or `private_key_jwt`.

With `Config.JAR` set, authorization requests are signed request objects
(RFC 9101), so their parameters cannot be altered on the way:
```go
client, _ := oidc.NewClient(prov, oidc.Config{ /* ... */ PrivateKeyJWT: &oidc.PrivateKeyJWTConfig{ /* ... */ }, JAR: true})
req, _ := client.AuthCodeURL()          // URL carries client_id, response_type, scope and request
req, _ = client.PushAuthCodeURL(ctx)    // the pushed form carries only client_id, request and the client assertion
```
- The object is signed with the `private_key_jwt` key and typed
  `oauth-authz-req+jwt`. It carries every authorization parameter plus
  `iss` (the client), `aud` (the issuer), `iat`, `nbf`, a five-minute `exp`
  and a random `jti`; `req.Expiry` says when a by-value URL stops working.
- `NewClient` fails if the provider sets `require_signed_request_object`
  without `JAR`, or does not list the key's algorithm in
  `request_object_signing_alg_values_supported`.

With `Config.DPoP` set, tokens are bound to the client's key (RFC 9449):
```go
prover, _ := dpop.NewProver(jwt.ES256, key) // keep key as long as the tokens
client, _ := oidc.NewClient(prov, oidc.Config{ /* ... */ DPoP: prover})
res, err := client.Exchange(ctx, req, state, code)
api := client.HTTPClient(ctx, res.Token) // sends "Authorization: DPoP" with a proof per request
```
- The authorization code is bound to the key: through `dpop_jkt`, or a DPoP
  proof on the pushed request.
- Token requests and refreshes carry proofs. `Exchange` fails unless the
  provider issues a `DPoP` token, rather than silently falling back to
  Bearer.
- Server-provided nonces are remembered per origin, and a request rejected
  with `use_dpop_nonce` is retried once with the new nonce. With
  `private_key_jwt`, the retry carries a freshly signed client assertion.
- `UserInfo` sends a DPoP token with the DPoP scheme and a proof.

### DPoP resource server
```go
tokens, _ := jwt.NewVerifier(keys, jwt.WithAlgorithms(jwt.ES256), jwt.WithIssuer(iss),
	jwt.WithAudience("api"), jwt.WithExpectedType("at+jwt"),
	jwt.WithConfirmationClaim()) // the binding is checked by dpop.Authenticator
proofs, _ := dpop.NewVerifier(dpop.WithAlgorithms(jwt.ES256),
	dpop.WithReplayCache(jwt.NewMemoryReplayCache())) // or dpop.WithoutReplayCheck()
auth, _ := dpop.NewAuthenticator(tokens, proofs)

at, err := dpop.AccessToken(r.Header.Get("Authorization"))
p, err := auth.Authenticate(ctx, dpop.Request{
	Method: r.Method, URL: "https://api.example.com" + r.URL.RequestURI(), // the external URL
	Proofs: r.Header.Values("DPoP"), AccessToken: at,
})
// on failure: 401 with WWW-Authenticate: proofs.Challenge(err)
```
Proof checks (RFC 9449 §4.3):
- exactly one `DPoP` header; `typ` is `dpop+jwt`; an asymmetric `alg` from
  the allow-list; the signature verifies with the embedded public key, which
  must not contain private key material
- `htm` equals the method and `htu` the request URI, compared after
  RFC 3986 normalization and ignoring query and fragment
- `iat` is at most `WithMaxAge` (default 1 minute) old and at most
  `WithLeeway` (default 10 seconds) in the future
- `ath` matches the access token, and the key's thumbprint matches the
  token's `cnf.jkt`
- `jti` has not been seen before (a replay cache, or an explicit opt-out, is
  required); proofs that fail any other check are not recorded
- optionally a server nonce (`WithNonce`); a missing or stale one returns
  `dpop.ErrUseNonce`

For opaque access tokens, pass an `Introspector` instead of a
`jwt.Verifier`. It asks the authorization server's RFC 7662 introspection
endpoint, authenticating with `client_secret_basic`, and the proof key is
then checked against the response's `cnf.jkt` (RFC 9449 §6.2):
```go
tokens, _ := dpop.NewIntrospector(dpop.IntrospectionConfig{
	Endpoint: "https://as.example.com/introspect",
	ClientID: "api", ClientSecret: secret, Issuer: iss,
	Audiences:         []string{"api"},
	ConfirmationClaim: true, // the binding is checked by dpop.Authenticator
})
auth, _ := dpop.NewAuthenticator(tokens, proofs)
```
`"active": false`, an expired `exp`, a future `nbf`, an `aud` without an
accepted audience, a different `iss` or a non-string `scope` fail with
`dpop.ErrInactiveToken`. A failed request, a redirect, or an unparsable
response, with no boolean `active`, is an error that does not wrap
`authent.ErrUnauthenticated`. The endpoint must be https, redirects are
never followed, and the default client times out after 10 seconds. `iss`
is optional in RFC 7662; set `RequireIssuer` to reject responses without
it.

### TOTP
```go
key, _ := totp.GenerateKey()                       // SHA1, 6 digits, 30 s: what every app supports
uri, _ := key.URI("Example", "alice@example.com")  // show as a QR code
counter, err := key.Verify(code, time.Now(), totp.DefaultSkew) // confirm enrollment
// store totp.Credential{Subject: "u1", Key: key, LastCounter: counter}

auth, _ := totp.NewAuthenticator(store) // store implements totp.Store
p, err := auth.Authenticate(ctx, "u1", code)
```
- Codes are compared in constant time, and the previous and next time steps
  are accepted by default.
- A code can be used only once. `Store.AdvanceCounter` must be an atomic
  compare-and-set, so two concurrent logins cannot both use one code.
- Secrets are at least 128 bits. They must be stored readable, so encrypt
  them at rest. Rate limiting failed attempts is up to the caller.

Counter-based tokens (HOTP, RFC 4226) use a `HOTPAuthenticator`:
```go
uri, _ := key.HOTPURI("Example", "alice@example.com", 0)
hotp, _ := totp.NewHOTPAuthenticator(hstore) // hstore implements totp.HOTPStore
p, err := hotp.Authenticate(ctx, "u1", code)
p, err = hotp.Resync(ctx, "u1", code1, code2) // after the token ran ahead
```
- `Authenticate` accepts the next 10 counter values (`WithLookAhead`, at
  most 50) and moves the stored counter past the match, so earlier codes
  stop working.
- `Resync` needs two consecutive codes within the next 1000 values
  (`WithResyncWindow`), as RFC 4226 §7.4 describes. Every `Resync`
  computes up to two HMACs per value in the window (2,000 by default,
  20,000 at the maximum), so rate-limit it more tightly than logins.
- `HOTPStore.AdvanceHOTPCounter(ctx, subject, first, next)` must be an
  atomic compare-and-set. It moves the counter to `next` only if the
  stored counter is still at most `first`, so a code read from a stale
  lookup cannot be used twice.

Recovery codes let a user log in after losing the second factor:
```go
codes, hashes, _ := totp.GenerateRecoveryCodes(10) // show codes once, store hashes
recovery, _ := totp.NewRecoveryAuthenticator(rstore) // rstore implements totp.RecoveryStore
p, err := recovery.Authenticate(ctx, "u1", code)     // p.Method is authent.MethodRecovery
```
- Each code has 120 random bits and is stored as its SHA-256 (NIST
  SP 800-63B requires 112 bits for an unsalted fast hash).
- Hyphens, spaces and ASCII case are ignored when a code is entered.
  Anything else that is not a code is rejected before the store is
  queried.
- `RecoveryStore.ConsumeRecoveryCode` must check and remove the hash
  atomically, so a code works only once.

`totp.ParseURI` reads an `otpauth://totp` or `otpauth://hotp` URI back into
a `Key`, for example to import keys from another system:
```go
p, err := totp.ParseURI(uri) // p.Key, p.Issuer, p.Account, p.Counter (HOTP)
```
The parser is strict. It rejects unknown, repeated or empty parameters,
non-canonical base32 and numbers, an `issuer` parameter that differs from
the label, and keys that fail validation. Missing `algorithm`, `digits` and
`period` default to SHA1, 6 and 30 seconds.

### WebAuthn
```go
rp, _ := webauthn.New(webauthn.Config{
	RPID:    "example.com",
	RPName:  "Example",
	Origins: []string{"https://example.com"},
}, store) // store implements webauthn.CredentialStore

// Registration
handle, _ := webauthn.NewUserHandle() // once per user; store it with the user
opts, ch, _ := rp.BeginRegistration(webauthn.User{Subject: "u1", Handle: handle, Name: "alice"}, existing)
// send opts as JSON, keep ch server-side (e.g. JSON in a session value) ...
cred, err := rp.FinishRegistration(ctx, ch, responseJSON) // then save cred

// Login: second factor for a known user, or a passkey without a username
opts, ch, _ = rp.BeginLogin(userCreds) // or rp.BeginDiscoverableLogin()
p, cred, err := rp.FinishLogin(ctx, ch, responseJSON)
```
In the browser, pass the options to
`PublicKeyCredential.parseCreationOptionsFromJSON` (or
`parseRequestOptionsFromJSON`) and send back `credential.toJSON()`.

`FinishRegistration` and `FinishLogin` check:
- the challenge (single ceremony type, expiry), the origin, the RP ID hash,
  and that `crossOrigin` is false
- the user presence flag, and the user verification flag when
  `UserVerification` is `required`
- the credential algorithm against an allow-list, with the key type and
  curve bound to the algorithm (ES256/384/512, EdDSA, RS256, PS256)
- the attestation statement for the `none`, `packed` and `fido-u2f`
  formats. Other formats are rejected. Set `AttestationRoots` to require a
  certificate chain to known roots.
- that the credential is not already registered, belongs to the expected
  user, and was in `allowCredentials`
- the signature counter, which must increase unless it is always 0, and
  that backup eligibility does not change

CBOR is decoded strictly: no tags, floats, indefinite lengths, duplicate
map keys or trailing bytes, with bounds on depth and length.

### HTTP middleware
```go
auth := httpauth.Any(
	httpauth.APIKey(keys),                  // only claims tokens with its prefix, so list it first
	httpauth.Bearer(verifier),              // Authorization: Bearer <JWT>
	httpauth.SessionCookie(sessions, "sid"), // checks the CSRF token on unsafe methods
)
mux.Handle("/api/", httpauth.Require(auth)(api))   // 401 without valid credentials
mux.Handle("/", httpauth.Optional(auth)(site))     // anonymous allowed, bad credentials are not

func handler(w http.ResponseWriter, r *http.Request) {
	p, ok := authent.FromContext(r.Context())
	// ...
}
```
- Errors wrapping `authent.ErrUnauthenticated` give 401. Bearer
  authenticators add `WWW-Authenticate: Bearer`, with
  `error="invalid_token"` when a token was rejected (RFC 6750 §3).
  `httpauth.ErrForbidden`, including `httpauth.ErrCSRF`, gives 403. Any
  other error, such as a store failure, gives 500 without details.
  `httpauth.WithErrorHandler` replaces these responses, for example with a
  redirect to a login page.
- `Optional` passes a request without a Principal only when it carries no
  credentials (`httpauth.ErrNoCredentials`). Rejected credentials are
  never downgraded to anonymous.
- Bearer tokens are read from the `Authorization` header only, never from
  the query string or form body. Several `Authorization` headers, or
  several session cookies with the same name, are rejected.
- `SessionCookie` requires the session's CSRF token on methods other than
  GET, HEAD, OPTIONS and TRACE, in the `X-CSRF-Token` header or the
  `csrf_token` form field. Change where it is read with
  `httpauth.WithCSRFToken`, or pass `nil` to turn the check off. To embed
  the token in a page, load the session with `sessions.Get` and use
  `s.CSRFToken()`.
- `authent.NewContext` and `authent.FromContext` carry the Principal for
  any transport.

#### gRPC
gRPC interceptors are not included, because `google.golang.org/grpc` is
outside the dependency policy. An interceptor is a few lines on top of
`jwt.Verifier` and the context helpers:
```go
func authUnary(v *jwt.Verifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		vals := md.Get("authorization")
		if len(vals) != 1 {
			return nil, status.Error(codes.Unauthenticated, "missing credentials")
		}
		token, err := httpauth.BearerToken(vals[0])
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		p, err := v.Authenticate(ctx, token)
		if errors.Is(err, authent.ErrUnauthenticated) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		if err != nil {
			return nil, status.Error(codes.Internal, "internal error")
		}
		return next(authent.NewContext(ctx, p), req)
	}
}
```

### ReBAC
```go
schema, _ := rebac.NewSchema(
	rebac.Type("user"),
	rebac.Type("group", rebac.Relation("member", rebac.Direct("user", "group#member"))),
	rebac.Type("folder",
		rebac.Relation("owner", rebac.Direct("user")),
		rebac.Relation("viewer", rebac.Union(rebac.Direct("user", "group#member", "user:*"), rebac.Computed("owner"))),
	),
	rebac.Type("doc",
		rebac.Relation("parent", rebac.Direct("folder")),
		rebac.Relation("banned", rebac.Direct("user")),
		rebac.Relation("viewer", rebac.Exclusion(
			rebac.Union(rebac.Direct("user"), rebac.TupleToUserset("parent", "viewer")),
			rebac.Computed("banned"))),
	),
)
engine, _ := rebac.NewEngine(schema, rebac.NewMemoryStore())
rev, err := engine.Write(ctx, []rebac.Tuple{
	rebac.MustParseTuple("folder:root#viewer@group:eng#member"),
	rebac.MustParseTuple("doc:readme#parent@folder:root"),
}, nil)
// Store rev with the document. AtLeast(rev) makes the check fail rather
// than read a store that has not seen the write.
ok, err := engine.Check(ctx, rebac.Obj("doc", "readme"), "viewer", rebac.Sub("user", "alice"), rebac.AtLeast(rev))
```
- Writes that do not match the schema are rejected. Examples are a subject
  type the relation does not allow, or a write to a computed-only relation.
- Relations that depend on themselves through `Computed` alone are rejected
  when the schema is built.
- Cycles in the data follow the well-founded semantics of the rewrites. A
  cycle never grants by itself: groups that only contain each other have
  no members, and a cycle cannot cancel the subtraction of an
  `Exclusion`. A relation that depends on its own exclusion ("viewers are
  the users who are not viewers") has no answer, and `Check` fails closed
  with `ErrExclusionCycle`.
- Depth and evaluation count are bounded. Exceeding either limit returns
  `false` with `ErrTooComplex`.
- Store errors fail closed: `Check` returns `false` with the error.
- Every `Write` moves the store to a new `Revision`, Zanzibar's consistency
  token ("zookie"). A query reads one revision, the latest, so it never
  mixes data from before and after a write. `AtLeast(rev)` makes a query
  fail with `ErrFutureRevision` if the store has not reached `rev`, such as
  a replica that is behind.
- `TupleStore.Changes` lists the writes and deletes after a revision, and
  `Engine.Watch` streams them as they happen. `Prune` on `MemoryStore` and
  `SQLStore` discards history; reads and changes before the pruned
  revision then fail with `ErrRevisionExpired`.
- `WithCheckCache(n)` keeps up to `n` check results across calls. A result
  answers a later check only if it was computed at the store's latest
  revision, which every check reads, so a revoke takes effect at once.
  Errors are not cached.
- `CheckBulk` runs many checks in one call. They share store reads and
  the relations they decide on the way; results come back in order, each
  with its own error.
- `Expand` returns the userset tree of an `object#relation`: union,
  intersection and exclusion nodes down to the subjects of tuples. It
  follows `Computed` and `TupleToUserset`; usersets named by tuples, such
  as `group:eng#member`, are leaves to expand with another call.
- `WithConcurrency(n)` evaluates up to `n` branches of a check (and items
  of `CheckBulk`) in parallel, which helps with network stores. Once a
  branch decides, its siblings are cancelled. The evaluation limit is
  shared by all branches: a check that exceeds it fails, even if a branch
  granted first.

To check permissions for an authenticated request, map its Principal to a
subject:
```go
sub, err := rebac.SubjectOf(p, "user") // user:<p.Subject>; an empty or "*" subject is an error
ok, err := engine.Check(ctx, rebac.Obj("doc", id), "viewer", sub)

// or as middleware, inside httpauth.Require:
mux.Handle("GET /docs/{id}", httpauth.Require(auth)(
	httpauth.RequirePermission(engine, "viewer", "user", func(r *http.Request) (rebac.Object, error) {
		return rebac.Obj("doc", r.PathValue("id")), nil
	})(docHandler)))
```
`RequirePermission` responds 403 when the check is denied or the object
ID is invalid, and 500 when the check fails.

#### Persistent tuple storage
```go
import _ "github.com/jackc/pgx/v5/stdlib" // or any database/sql driver

db, _ := sql.Open("pgx", dsn)
store, _ := rebac.NewSQLStore(db, rebac.PostgreSQL) // also rebac.MySQL, rebac.SQLite
store.CreateTable(ctx) // or apply store.CreateTableStatements() with your migration tool
engine, _ := rebac.NewEngine(schema, store)
```
- `SQLStore` works through `database/sql` and imports no driver; you choose
  one.
- Identifiers are compared byte by byte. `CreateTable` uses `COLLATE "C"`
  on PostgreSQL and `VARBINARY` on MySQL, so `Alice` and `alice` are
  different subjects whatever the server collation. Rows that do not
  exactly match a lookup are discarded anyway, and rows that are not valid
  tuples make the read fail.
- A write is one transaction. It locks the row of the `<table>_revision`
  table that holds the latest revision, so writes are serialized and
  revisions follow commit order. A delete keeps the row with the revision
  it was deleted at, for reads at older revisions and for `Changes`, until
  `Prune` removes it.
- A read releases its connection before returning tuples, so a pool with a
  single connection (common for SQLite) does not deadlock on recursive
  checks. It reads the latest and the pruned revision in the same
  statement, so a concurrent `Prune` is detected, not silently read
  around.
- `rebactest.TestTupleStore` is a conformance suite for `TupleStore`
  implementations. Run it against your own store, or against `SQLStore`
  with your database and driver.

## Feature status

See [FEATURES.md](FEATURES.md) for what is implemented, what is not yet,
and what is out of scope.

## Testing
```
go test -race ./...
go test ./jwt -run '^$' -fuzz FuzzVerify -fuzztime 30s
go test ./webauthn -run '^$' -fuzz FuzzCBOR -fuzztime 30s
go test ./apikey -run '^$' -fuzz FuzzParse -fuzztime 30s
go test ./totp -run '^$' -fuzz FuzzParseURI -fuzztime 30s
```
`jwt/testdata/gen_openssl_vectors.py` generates `jwt/testdata/openssl_vectors.json`
and `jwt/testdata/gen_openssl_x5c.py` generates the certificate chain in
`jwt/testdata/openssl_x5c.json` with OpenSSL. `webauthn/testdata/extract_spec_vectors.py` extracts
`webauthn/testdata/spec_vectors.json` from the test vectors in the WebAuthn
Level 3 specification. The TOTP tests use the RFC 4226 and RFC 6238
vectors. These vectors come from sources independent of this library.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow and commit message conventions.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
