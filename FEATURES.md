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
| Password policy (length, blocklist, breached-password check) | ✅ | Configurable limits, exact-match blocklist, Pwned Passwords range lookup and NFC normalization for new passwords |
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
| JWK thumbprint (RFC 7638) | ✅ | |
| Rejection of sender-constrained (`cnf`) tokens as bearer tokens | ✅ | Opt out with `WithConfirmationClaim` when the binding is verified elsewhere |
| Verification with a key embedded in the `jwk` header | ✅ | Separate `VerifyWithEmbeddedKey` API for DPoP proofs; `Verifier` never uses it |
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
| Discovery | ✅ | Requires an exact issuer match and https endpoints (including `userinfo_endpoint` when present) |
| Authorization code flow with PKCE (S256) | ✅ | |
| `state` and `nonce` generation and checks | ✅ | Compared in constant time |
| ID token verification | ✅ | Signature, `iss`, `aud`, `exp`, `nbf`, `iat` |
| `azp` and `at_hash` checks | ✅ | |
| HMAC-signed ID tokens rejected by default | ✅ | |
| `client_secret_basic` / `client_secret_post` | ✅ | Through `x/oauth2` |
| Distinguishing rejected exchanges from network errors | ✅ | |
| UserInfo endpoint | ✅ | `sub` must match the ID token; https only; redirects are not followed; Bearer or DPoP tokens |
| Signed UserInfo responses (`application/jwt`) | ⬜ | Currently rejected; needs JWT verification without `exp`. Encrypted responses are out of scope along with JWE |
| Refresh token helper | ⬜ | `HTTPClient` refreshes through `x/oauth2`, but refreshed ID tokens are not verified and `private_key_jwt` clients cannot refresh |
| Calling APIs with the access token (`HTTPClient`) | ✅ | Bearer, or DPoP when configured |
| `max_age`, `auth_time` and `acr` enforcement | ⬜ | |
| `private_key_jwt` client authentication | ✅ | Asymmetric JWT assertion on each code exchange; issuer audience per RFC 10070 |
| RP-initiated, front-channel and back-channel logout | ⬜ | |
| Pushed authorization requests (RFC 9126) | ✅ | `PushAuthCodeURL`; honors `require_pushed_authorization_requests`; client secret or `private_key_jwt` |
| JWT-secured authorization requests (JAR, RFC 9101) | ⬜ | |
| DPoP-bound tokens (RFC 9449) | ✅ | `dpop_jkt` or a proof on the pushed request; `Exchange` rejects a Bearer downgrade |
| Implicit and hybrid flows (`c_hash`) | ➖ | Discouraged by current OAuth security best practice |

## dpop

| Feature | Status | Notes |
|---|---|---|
| Proof creation (`Prover`) | ✅ | RSA, ECDSA and Ed25519 keys; 128-bit `jti` |
| Client `http.RoundTripper` | ✅ | Proof per request, `ath` with access tokens, refuses non-DPoP tokens |
| Server-provided nonces on the client | ✅ | Kept per origin; one retry on `use_dpop_nonce` (400 and 401) |
| Proof verification (RFC 9449 §4.3) | ✅ | All twelve checks; `htu` compared after RFC 3986 normalization |
| Replay detection | ✅ | `ReplayCache` interface and `MemoryReplayCache`; opting out must be explicit |
| Server nonce validation | ✅ | Pluggable `WithNonce`; issuing nonces is up to the caller |
| Resource server `Authenticator` for JWT access tokens | ✅ | Checks `cnf.jkt` against the proof key |
| `WWW-Authenticate` challenges | ✅ | `Challenge` with `algs` and error codes |
| Opaque tokens (introspection, RFC 9449 §6.2) | ⬜ | Use `Verifier` with `Request.JKT` from the introspection response |
| Authorization server side (issuing bound tokens) | ➖ | Same reason as the OAuth 2.0 authorization server below |
| Shared replay cache stores (Redis, SQL) | ⬜ | |

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
| Persistent stores: `SQLStore` for PostgreSQL, MySQL and SQLite | ✅ | Through `database/sql`; bring your own driver. Byte-wise identifier comparison |
| `TupleStore` conformance suite | ✅ | `rebactest.TestTupleStore` |
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

## totp

| Feature | Status | Notes |
|---|---|---|
| HOTP (RFC 4226) and TOTP (RFC 6238) | ✅ | SHA1, SHA256, SHA512; 6 to 8 digits; any whole-second period |
| Key generation | ✅ | Secret length matches the hash output; at least 128 bits required |
| `otpauth://` URI and base32 secret | ✅ | For QR codes and manual entry |
| Clock skew window | ✅ | Default ±1 step, at most ±5 |
| Constant-time comparison | ✅ | |
| Replay protection | ✅ | `Store.AdvanceCounter` is a compare-and-set on the last used step |
| Pluggable store | ✅ | `Store` interface |
| Recovery codes | ✅ | 120-bit single-use codes stored as SHA-256; `RecoveryStore.ConsumeRecoveryCode` removes a code atomically |
| HOTP counter-based authentication | ✅ | `HOTPAuthenticator`: look-ahead window, resynchronization with two consecutive codes (RFC 4226 §7.4), atomic counter advance; `Key.HOTPURI` |
| Parsing `otpauth://` URIs | ⬜ | |
| Encrypting secrets at rest | ➖ | Depends on the deployment's key management; belongs in the store |
| Rate limiting | ➖ | Depends on deployment; belongs in the caller |

## webauthn

| Feature | Status | Notes |
|---|---|---|
| Registration and authentication ceremonies | ✅ | WebAuthn Level 3 §7.1 and §7.2 |
| JSON options and responses | ✅ | `parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON` and `toJSON()` formats |
| Second-factor logins and discoverable (passkey) logins | ✅ | `BeginLogin` and `BeginDiscoverableLogin` |
| Challenge, origin, RP ID hash, `type` checks | ✅ | Challenges expire and are bound to one ceremony type |
| User presence and user verification | ✅ | `UserVerification` policy; UV result in `Principal.Claims` |
| ES256/384/512, EdDSA (Ed25519), RS256, PS256 | ✅ | Key type and curve must match the algorithm; RSA keys at least 2048 bits |
| Strict CBOR and authenticator data parsing | ✅ | No tags, floats or indefinite lengths; no duplicate keys or trailing bytes |
| Attestation formats `none`, `packed`, `fido-u2f` | ✅ | Self and basic attestation |
| Attestation trust roots | ✅ | `AttestationRoots` requires a chain to the given roots |
| Signature counter clone detection | ✅ | A counter that does not increase is rejected |
| Backup eligibility and state flags | ✅ | BE must not change; BS is stored |
| Duplicate credential and user handle checks | ✅ | |
| WebAuthn Level 3 test vectors | ✅ | §16 vectors, including rejected ones |
| Attestation formats `tpm`, `android-key`, `android-safetynet`, `apple` | ⬜ | Rejected; browsers send `none` unless attestation is requested |
| FIDO Metadata Service (MDS3) | ⬜ | |
| Ed448 | ⬜ | No Ed448 in the standard library |
| Cross-origin iframes (`crossOrigin`, `topOrigin`) | ⬜ | Rejected |
| Related origins and native app origins | ⬜ | Origins must be https within the RP ID |
| Extensions (`credProps`, `prf`, `largeBlob`, `appid`) | ⬜ | Authenticator extension outputs are parsed but not used |
| Conditional create (registration without user presence) | ⬜ | User presence is always required |
| Single-use enforcement of challenges | ➖ | The caller keeps the `Challenge` and deletes it after use |

## Cross-cutting

| Feature | Status | Notes |
|---|---|---|
| Framework-agnostic core | ✅ | |
| Dependencies limited to the standard library and `golang.org/x` | ✅ | |
| Unified `authent.Principal` and `ErrUnauthenticated` | ✅ | Infrastructure errors do not wrap `ErrUnauthenticated` |
| Independent test vectors (OpenSSL, RFCs) and fuzz tests | ✅ | |
| `net/http` middleware | ✅ | `httpauth`: bearer JWTs, session cookies and API keys; `Require` and `Optional`; CSRF check on unsafe methods; Principal in the context via `authent.NewContext` |
| gRPC interceptors | ➖ | A gRPC dependency is outside the dependency policy; an interceptor is a few lines on top of `jwt.Verifier` and `authent.NewContext` (example in the README) |
| Mapping a Principal to a ReBAC subject | ✅ | `rebac.SubjectOf`; `httpauth.RequirePermission` checks a permission per request. The issuer is not part of the subject |
| Observability hooks (logging, metrics, tracing) | ⬜ | |
| API keys / opaque tokens | ✅ | `apikey`: prefixed keys with a CRC-32 checksum, SHA-256 at rest, expiry and revocation |
| Multi-factor authentication (TOTP, WebAuthn) | ✅ | See the `totp` and `webauthn` sections |
| Recording several factors in a session (`amr`, step-up) | ⬜ | `Session.AuthMethod` holds one method |
| OAuth 2.0 authorization server (issuing endpoints) | ➖ | A separate product; the `jwt` package covers token signing |
