# Feature status

Legend:

- ✅ Implemented
- ⬜ Not implemented yet
- ➖ Not planned: out of scope by design; the reason is noted

## password

| Feature | Status | Notes |
|---|---|---|
| Argon2id hashing | ✅ | Defaults to RFC 9106 second recommendation (64 MiB, t=3, p=4) |
| PHC string format | ✅ | `$argon2id$v=19$m=...,t=...,p=...$salt$hash` |
| Constant-time verification | ✅ | |
| Bounds on parameters read from stored hashes | ✅ | A tampered hash cannot force huge memory or CPU use |
| `NeedsRehash` and automatic upgrade on login | ✅ | Requires the store to implement `CredentialUpdater` |
| Timing-safe handling of unknown users | ✅ | Unknown users are verified against a dummy hash |
| Pluggable credential store | ✅ | `CredentialStore` interface |
| Verifying legacy hashes (bcrypt, scrypt, PBKDF2) | ⬜ | Would help migrations |
| Pepper (server-side secret) | ⬜ | |
| Password policy (length, breached-password check) | ⬜ | |
| Password reset tokens | ⬜ | |
| Rate limiting and account lockout | ➖ | Depends on deployment; belongs in the caller |

## jwt

| Feature | Status | Notes |
|---|---|---|
| JWS compact serialization: sign and verify | ✅ | |
| HS256/384/512, RS256/384/512, PS256/384/512 | ✅ | RSA keys must be at least 2048 bits; HMAC keys at least the hash size |
| ES256/384/512 | ✅ | Fixed-width R‖S only; DER is rejected |
| EdDSA (Ed25519) | ✅ | |
| EdDSA (Ed448) | ⬜ | No Ed448 in the standard library |
| Required algorithm allow-list; `none` always rejected | ✅ | |
| Key and algorithm binding (algorithm-confusion protection) | ✅ | JWK `alg`, `use` and `key_ops` are honored |
| Strict parsing | ✅ | Case-sensitive, no duplicate members, canonical base64url, size limit |
| Rejection of `crit`, `b64`, `zip` and `enc` headers | ✅ | |
| Never fetching keys from `jku`, `x5u` or `jwk` headers | ✅ | These headers are ignored |
| Claim validation: `exp` (required), `nbf`, `iat`, `iss`, `aud` | ✅ | `iss` and `aud` checks must be opted out of explicitly |
| Clock skew leeway | ✅ | |
| `typ` check | ✅ | For example `at+jwt` (RFC 9068) |
| Conversion to `authent.Principal` | ✅ | Uses `auth_time` when present |
| JWK parse and marshal for RSA, EC (P-256/384/521) and OKP (Ed25519) public keys | ✅ | EC points are validated on the curve |
| JWK Set parsing that skips unusable keys | ✅ | |
| `StaticKeySet` | ✅ | |
| `RemoteKeySet` | ✅ | TTL, refetch on unknown `kid`, refresh throttling, stale-on-error, concurrent fetch deduplication |
| Refresh interval from `Cache-Control` | ⬜ | The interval is fixed |
| JWK thumbprint (RFC 7638) | ⬜ | |
| Parsing private JWKs | ⬜ | Signing keys are passed as Go crypto keys |
| `jti` replay detection | ⬜ | Needs a store |
| Maximum token age / `auth_time` limits | ⬜ | |
| `x5c` certificate chain validation | ⬜ | |
| JWE (encryption) | ➖ | Large attack surface; not needed for signed tokens |
| JWS JSON serialization and nested JWTs | ➖ | Rarely needed; increases attack surface |
| Symmetric keys in JWK JSON | ➖ | Kept out to avoid leaking secrets |

## session

| Feature | Status | Notes |
|---|---|---|
| Create / Get / Save / Rotate / Destroy | ✅ | |
| Idle and absolute timeouts | ✅ | |
| Throttled activity updates | ✅ | `WithTouchInterval` |
| Store keyed by the token hash | ✅ | A leaked store does not yield usable tokens |
| Validation of the token format before the store lookup | ✅ | |
| Per-session CSRF token | ✅ | Synchronizer token pattern; compared in constant time |
| Pluggable store and `MemoryStore` | ✅ | |
| Redis or SQL stores | ⬜ | |
| Revoking all sessions of a subject ("log out everywhere") | ⬜ | Needs a subject index in the store |
| Listing a subject's active sessions | ⬜ | |
| Conflict detection on concurrent saves | ⬜ | Currently last write wins |
| Structured session values | ⬜ | Currently `map[string]string` |
| Cookie helpers | ➖ | The core does not depend on HTTP; planned for an adapter package |

## oidc

| Feature | Status | Notes |
|---|---|---|
| Discovery | ✅ | Requires an exact issuer match and https endpoints |
| Authorization code flow with PKCE (S256) | ✅ | |
| `state` and `nonce` generation and checks | ✅ | Compared in constant time |
| ID token verification | ✅ | Signature, `iss`, `aud`, `exp`, `nbf`, `iat` |
| `azp` and `at_hash` checks | ✅ | |
| HMAC-signed ID tokens rejected by default | ✅ | |
| `client_secret_basic` / `client_secret_post` | ✅ | Through `x/oauth2` |
| Distinguishing rejected exchanges from network errors | ✅ | |
| UserInfo endpoint | ⬜ | |
| Refresh token helper | ⬜ | The `oauth2.Token` is returned and can be used with `x/oauth2` |
| `max_age`, `auth_time` and `acr` enforcement | ⬜ | |
| `private_key_jwt` client authentication | ⬜ | |
| RP-initiated, front-channel and back-channel logout | ⬜ | |
| PAR (RFC 9126) and DPoP (RFC 9449) | ⬜ | |
| Implicit and hybrid flows (`c_hash`) | ➖ | Discouraged by current OAuth security best practice |

## rebac

| Feature | Status | Notes |
|---|---|---|
| Schema definition with a Go API | ✅ | |
| Schema validation | ✅ | Undefined references, tupleset rules, cycles through `Computed` |
| Rewrites: `Direct`, `Computed`, `TupleToUserset`, `Union`, `Intersection`, `Exclusion` | ✅ | |
| Usersets as subjects (`group:eng#member`) | ✅ | |
| Wildcard subjects (`user:*`) | ✅ | |
| `Check` | ✅ | Cuts off cycles in the data; caches positive results within a check |
| Depth and evaluation limits | ✅ | Exceeding them fails closed with `ErrTooComplex` |
| Fail closed on store errors | ✅ | A grant found through an independent branch still succeeds |
| Context cancellation | ✅ | |
| Write validation against the schema | ✅ | Batches are atomic |
| Tuple string format (parse and format) | ✅ | `doc:readme#viewer@user:alice` |
| `TupleStore` interface and `MemoryStore` | ✅ | `MemoryStore` supports reverse (subject) filters |
| Persistent stores (PostgreSQL, etc.) | ⬜ | |
| `Expand` (userset tree) | ⬜ | |
| `ListObjects` / `ListSubjects` | ⬜ | |
| Consistency tokens (zookies) | ⬜ | |
| Text schema DSL | ⬜ | |
| Caveats / conditional tuples (ABAC) | ⬜ | |
| Bulk check | ⬜ | |
| Parallel branch evaluation | ⬜ | Branches are evaluated sequentially with short-circuiting |
| Check result caching across requests | ⬜ | |
| Watch API / change log | ⬜ | |
| Exact semantics for `Exclusion` over data cycles | ⬜ | A cycle reached from the subtracted side evaluates to `false` |

## Cross-cutting

| Feature | Status | Notes |
|---|---|---|
| Framework-agnostic core | ✅ | |
| Dependencies limited to the standard library and `golang.org/x` | ✅ | |
| Unified `authent.Principal` and `ErrUnauthenticated` | ✅ | Infrastructure errors do not wrap `ErrUnauthenticated` |
| Independent test vectors (OpenSSL, RFCs) and fuzz tests | ✅ | |
| `net/http` middleware | ⬜ | |
| gRPC interceptors | ⬜ | |
| Mapping a Principal to a ReBAC subject | ⬜ | |
| Observability hooks (logging, metrics, tracing) | ⬜ | |
| API keys / opaque tokens | ⬜ | |
| Multi-factor authentication (TOTP, WebAuthn) | ⬜ | |
| OAuth 2.0 authorization server (issuing endpoints) | ➖ | A separate product; the `jwt` package covers token signing |
