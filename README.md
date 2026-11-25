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
| `oidc` | OpenID Connect relying party (authorization code flow with PKCE S256, PAR, DPoP) |
| `dpop` | DPoP (RFC 9449): client proofs and transport, resource server verification |
| `totp` | Time-based one-time passwords (RFC 6238) with replay protection |
| `webauthn` | WebAuthn relying party: passkeys and security keys |
| `rebac` | Zanzibar-style relationship-based access control (ReBAC) |

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
  - `exp` is required.
  - Tokens with a `cnf` claim (sender-constrained, e.g. DPoP-bound) are
    rejected unless `jwt.WithConfirmationClaim()` is set, so a stolen bound
    token cannot be replayed as a bearer token (RFC 9449 §7.2).
  - Headers with `crit`, `b64` or `zip` are rejected.
  - `jku`, `x5u` and `jwk` headers are never used to find keys.
- **Encoding**
  - JSON is decoded with `encoding/json/v2`: member names are matched
    case-sensitively and duplicate members are rejected.
  - Non-canonical base64url is rejected. This covers line breaks, padding
    and non-zero trailing bits.
- **Signatures and keys**
  - ECDSA signatures must use the fixed-width R‖S form.
  - RSA keys must be at least 2048 bits.
  - HMAC keys must be at least as long as the hash output.

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

### OIDC
```go
prov, _ := oidc.Discover(ctx, "https://accounts.example.com", nil)
client, _ := oidc.NewClient(prov, oidc.Config{ClientID: id, ClientSecret: secret, RedirectURL: cb})

req, _ := client.AuthCodeURL() // keep req.State, Nonce and CodeVerifier server-side
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

`UserInfo` calls the provider's UserInfo endpoint with the access token and
rejects the response unless its `sub` exactly matches the ID token's. Only
plain JSON responses are accepted, and redirects are not followed, so the
access token is never sent anywhere but the advertised https endpoint.

Pushed authorization requests (RFC 9126) send the parameters to the
provider over the back channel, so the browser only sees a `request_uri`:
```go
req, err := client.PushAuthCodeURL(ctx) // redirect to req.URL before req.Expiry
```
`AuthCodeURL` returns `oidc.ErrPARRequired` when the provider sets
`require_pushed_authorization_requests`. The client authenticates at the PAR
endpoint as at the token endpoint, with its secret or `private_key_jwt`.

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
	dpop.WithReplayCache(dpop.NewMemoryReplayCache())) // or dpop.WithoutReplayCheck()
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
engine.Write(ctx, []rebac.Tuple{
	rebac.MustParseTuple("folder:root#viewer@group:eng#member"),
	rebac.MustParseTuple("doc:readme#parent@folder:root"),
}, nil)
ok, err := engine.Check(ctx, rebac.Obj("doc", "readme"), "viewer", rebac.Sub("user", "alice"))
```
- Writes that do not match the schema are rejected. Examples are a subject
  type the relation does not allow, or a write to a computed-only relation.
- Relations that depend on themselves through `Computed` alone are rejected
  when the schema is built.
- Cycles in the data, such as groups that contain each other, are detected
  and cut off during evaluation.
- Depth and evaluation count are bounded. Exceeding either limit returns
  `false` with `ErrTooComplex`.
- Store errors fail closed: `Check` returns `false` with the error.

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
- A write is one transaction. A read releases its connection before
  returning tuples, so a pool with a single connection (common for SQLite)
  does not deadlock on recursive checks.
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
```
`jwt/testdata/gen_openssl_vectors.py` generates `jwt/testdata/openssl_vectors.json`
with OpenSSL. `webauthn/testdata/extract_spec_vectors.py` extracts
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
