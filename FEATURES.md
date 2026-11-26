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
| Verifying legacy hashes (bcrypt, scrypt, PBKDF2) | ✅ | Verify only: bcrypt (`$2a$`, `$2b$`, `$2y$`), Werkzeug scrypt and Django PBKDF2-SHA256, with bounded costs. Upgraded to Argon2id on login |
| Pepper (server-side secret) | ✅ | HMAC-SHA-256 before Argon2id; `keyid` in the PHC string; retired peppers verify and trigger a rehash; unknown key IDs fail closed |
| Password policy (length, blocklist, breached-password check) | ✅ | Configurable limits, exact-match blocklist, Pwned Passwords range lookup and NFC normalization for new passwords |
| Password reset tokens | ✅ | 256-bit tokens; the store keeps only the SHA-256 hash, subject and expiry; atomic single use; a new token invalidates the subject's older ones. `MemoryResetStore` included |
| Rate limiting and account lockout | ➖ | Depends on deployment; belongs in the caller |

## jwt

| Feature | Status | Notes |
|---|---|---|
| JWS compact serialization: sign and verify | ✅ | |
| HS256/384/512, RS256/384/512, PS256/384/512 | ✅ | RSA keys must be at least 2048 bits; HMAC keys at least the hash size |
| ES256/384/512 | ✅ | Fixed-width R‖S only; DER is rejected |
| EdDSA (Ed25519) | ✅ | |
| EdDSA (Ed448) | ➖ | No Ed448 in the standard library or golang.org/x/crypto |
| Required algorithm allow-list; `none` always rejected | ✅ | |
| Key and algorithm binding (algorithm-confusion protection) | ✅ | JWK `alg`, `use` and `key_ops` are honored |
| Strict parsing | ✅ | Case-sensitive, no duplicate members, canonical base64url, size limit |
| Rejection of `crit`, `b64`, `zip` and `enc` headers | ✅ | |
| Never fetching keys from `jku`, `x5u` or `jwk` headers | ✅ | These headers are ignored |
| Claim validation: `exp` (required), `nbf`, `iat`, `iss`, `aud` | ✅ | `iss` and `aud` checks must be opted out of explicitly; `WithOptionalExpiration` accepts a missing `exp`, for signed UserInfo responses |
| Clock skew leeway | ✅ | |
| `typ` check | ✅ | For example `at+jwt` (RFC 9068) |
| Conversion to `authent.Principal` | ✅ | Uses `auth_time` when present |
| JWK parse and marshal for RSA, EC (P-256/384/521) and OKP (Ed25519) public keys | ✅ | EC points are validated on the curve |
| JWK Set parsing that skips unusable keys | ✅ | |
| `StaticKeySet` | ✅ | |
| `RemoteKeySet` | ✅ | TTL, refetch on unknown `kid`, refresh throttling, stale-on-error, concurrent fetch deduplication |
| Refresh interval from `Cache-Control` | ✅ | `max-age` clamped between the minimum and maximum refresh intervals; `no-store` and `no-cache` use the minimum |
| JWK thumbprint (RFC 7638) | ✅ | |
| Rejection of sender-constrained (`cnf`) tokens as bearer tokens | ✅ | Opt out with `WithConfirmationClaim` when the binding is verified elsewhere |
| Verification with a key embedded in the `jwk` header | ✅ | Separate `VerifyWithEmbeddedKey` API for DPoP proofs; `Verifier` never uses it |
| Parsing private JWKs | ✅ | `ParsePrivateJWK` for RSA (all CRT values, validated), EC and Ed25519; private keys are never marshaled, and `ParseJWK`/`ParseJWKSet` reject or drop keys with private members |
| `jti` replay detection | ✅ | `WithReplayCache`; `jti` then required, scoped by `iss`, recorded only after every other check |
| Maximum token age / `auth_time` limits | ✅ | `WithMaxTokenAge` (requires `iat`) and `WithMaxAuthAge` (requires `auth_time`, rejects one in the future); the leeway applies as for `exp` |
| `x5c` certificate chain validation | ✅ | The leaf must certify the JWK's key, checked when parsed and again before use; `WithCertificateRoots` verifies the chain with `crypto/x509`. The token's `x5c` header is never used |
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
| Redis or SQL stores | ✅ | `SQLStore` for PostgreSQL, MySQL and SQLite through `database/sql`; bring your own driver. Expiry column with `DeleteExpired`. Redis with TTLs in the separate `github.com/tohshi/authent/redis` module (`redissession`) |
| Revoking all sessions of a subject ("log out everywhere") | ✅ | `RevokeAll`; every `Store` keeps a subject index. A concurrent rotation does not survive it |
| Listing a subject's active sessions | ✅ | `List` returns sessions without tokens; `Revoke` ends one by its handle, only for its own subject |
| Conflict detection on concurrent saves | ✅ | Versioned records with compare-and-swap in every store; `ErrConflict` on a lost race |
| Structured session values | ✅ | `Key[T]` stores typed values as JSON |
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
| Signed UserInfo responses (`application/jwt`) | ✅ | Signature, `iss` and `aud` verified like an ID token, `exp` optional, `sub` must match; `RequireSignedUserInfo` rejects unsigned ones. Encrypted responses are rejected; JWE is out of scope |
| Refresh token helper | ✅ | `Refresh` works with every client authentication method, including `private_key_jwt`, and with DPoP; it keeps a rotated refresh token and checks a new ID token against the original (OpenID Connect Core §12.2). `HTTPClient` refreshes the same way but discards new ID tokens |
| Calling APIs with the access token (`HTTPClient`) | ✅ | Bearer, or DPoP when configured |
| `max_age`, `auth_time` and `acr` enforcement | ✅ | `max_age` and `acr_values` sent with the request are kept in `AuthRequest`; `Exchange` then requires a recent enough `auth_time` and an `acr` from the requested values |
| `private_key_jwt` client authentication | ✅ | Asymmetric JWT assertion on each code exchange; issuer audience per RFC 10070 |
| RP-initiated, front-channel and back-channel logout | ✅ | `EndSessionURL` with `id_token_hint`, `post_logout_redirect_uri` and `state`; `FrontChannelLogout` requires `iss` and `sid`; `BackChannelLogout` checks `typ` `logout+jwt`, the event, `sub` or `sid`, no `nonce`, a fresh `iat` and a single-use `jti`. Both return a `Logout` that `Matches` the ID tokens of the ended sessions |
| Pushed authorization requests (RFC 9126) | ✅ | `PushAuthCodeURL`; honors `require_pushed_authorization_requests`; client secret or `private_key_jwt` |
| JWT-secured authorization requests (JAR, RFC 9101) | ✅ | `Config.JAR` signs every request with the `private_key_jwt` key: `typ` `oauth-authz-req+jwt`, `iss`, `aud`, `iat`, `nbf`, a five-minute `exp` and a random `jti`. Sent by value from `AuthCodeURL` or inside the pushed request; honors `require_signed_request_object` |
| DPoP-bound tokens (RFC 9449) | ✅ | `dpop_jkt` or a proof on the pushed request; `Exchange` rejects a Bearer downgrade |
| Implicit and hybrid flows (`c_hash`) | ➖ | Discouraged by current OAuth security best practice |

## dpop

| Feature | Status | Notes |
|---|---|---|
| Proof creation (`Prover`) | ✅ | RSA, ECDSA and Ed25519 keys; 128-bit `jti` |
| Client `http.RoundTripper` | ✅ | Proof per request, `ath` with access tokens, refuses non-DPoP tokens |
| Server-provided nonces on the client | ✅ | Kept per origin; one retry on `use_dpop_nonce` (400 and 401) |
| Proof verification (RFC 9449 §4.3) | ✅ | All twelve checks; `htu` compared after RFC 3986 normalization |
| Replay detection | ✅ | `jwt.ReplayCache` interface and `jwt.MemoryReplayCache`; opting out must be explicit |
| Server nonce validation | ✅ | Pluggable `WithNonce`; issuing nonces is up to the caller |
| Resource server `Authenticator` for JWT access tokens | ✅ | Checks `cnf.jkt` against the proof key |
| `WWW-Authenticate` challenges | ✅ | `Challenge` with `algs` and error codes |
| Opaque tokens (introspection, RFC 9449 §6.2) | ✅ | `Introspector` (RFC 7662, `client_secret_basic`) as the token verifier of `Authenticator`; the proof key must match `cnf.jkt` |
| Authorization server side (issuing bound tokens) | ➖ | Same reason as the OAuth 2.0 authorization server below |
| Shared replay cache stores (Redis, SQL) | ✅ | `jwt/sqlreplay` for PostgreSQL and SQLite; `redisreplay` (SET NX with an expiry) in the separate `redis` module; both pass the `jwt/replaytest` conformance suite against real servers |

## rebac

| Feature | Status | Notes |
|---|---|---|
| Schema definition with a Go API | ✅ | |
| Schema validation | ✅ | Undefined references, tupleset rules, cycles through `Computed` |
| Rewrites: `Direct`, `Computed`, `TupleToUserset`, `Union`, `Intersection`, `Exclusion` | ✅ | |
| Usersets as subjects (`group:eng#member`) | ✅ | |
| Wildcard subjects (`user:*`) | ✅ | |
| `Check` | ✅ | Caches decided relations within a call |
| Depth and evaluation limits | ✅ | Exceeding them fails closed with `ErrTooComplex` |
| Fail closed on store errors | ✅ | A grant found through an independent branch still succeeds |
| Context cancellation | ✅ | |
| Write validation against the schema | ✅ | Batches are atomic |
| Tuple string format (parse and format) | ✅ | `doc:readme#viewer@user:alice`, with a caveat `...@user:alice[office:{"ip":"10.0.0.1"}]`; fuzzed |
| `TupleStore` interface and `MemoryStore` | ✅ | `MemoryStore` indexes subjects for reverse (subject) filters |
| Persistent stores: `SQLStore` for PostgreSQL, MySQL and SQLite | ✅ | Through `database/sql`; bring your own driver. Byte-wise identifier comparison |
| `TupleStore` conformance suite | ✅ | `rebactest.TestTupleStore` |
| `Expand` (userset tree) | ✅ | Follows `Computed` and `TupleToUserset`; usersets named by tuples are leaves |
| `ListObjects` / `ListSubjects` | ✅ | Candidates from a walk over the tuples, filtered by `Check`, so every rewrite is exact; wildcards give "all except"; bounded and cancellable |
| Consistency tokens (zookies) | ✅ | `Write` returns a `Revision`; every query reads one revision; `AtLeast` fails with `ErrFutureRevision` when the store is behind |
| Text schema DSL | ⬜ | |
| Caveats / conditional tuples (ABAC) | ✅ | `Caveat` declares a Go function with typed parameters; tuples store a context; `WithContext` supplies the rest; missing parameters give `*MissingContextError`, never true |
| Bulk check | ✅ | `CheckBulk`: shared store reads and decided relations, ordered results, an error per item |
| Parallel branch evaluation | ✅ | `WithConcurrency`; decided branches cancel their siblings; the evaluation limit is shared by all branches and fails closed |
| Check result caching across requests | ✅ | `WithCheckCache`: bounded LRU keyed by check and revision; serves only results computed at the latest revision |
| Watch API / change log | ✅ | `TupleStore.Changes` and `Engine.Watch`; `Prune` discards old history, after which it fails with `ErrRevisionExpired` |
| Exact semantics for `Exclusion` over data cycles | ✅ | Well-founded semantics; a relation that depends on its own exclusion fails closed with `ErrExclusionCycle` |

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
| Parsing `otpauth://` URIs | ✅ | `ParseURI` for TOTP and HOTP; strict about parameters, encoding and the label; fuzzed |
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
| Ed448 | ➖ | No Ed448 in the standard library or golang.org/x/crypto |
| Cross-origin iframes (`crossOrigin`, `topOrigin`) | ✅ | `TopOrigins` lists the pages that may embed a ceremony; `crossOrigin` without `topOrigin` is rejected |
| Related origins and native app origins | ✅ | `RelatedOrigins` (WebAuthn L3 §5.11); `android:apk-key-hash:` app origins in `Origins`; iOS apps report `https://<RP ID>` |
| Extensions (`credProps`, `prf`, `largeBlob`, `appid`) | ✅ | `WithExtensions`; `ExtensionOutputs` holds the client outputs of requested extensions and all authenticator outputs; `appid` changes the expected RP ID hash only when requested and reported as used |
| Conditional create (registration without user presence) | ✅ | `WithConditionalCreate` per registration (`mediation: "conditional"`); only then may the UP flag be unset |
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
| Recording several factors in a session (`amr`, step-up) | ✅ | `Session.Factors` with times; `Manager.StepUp` rotates the token; `AuthenticatedSince` checks required factors and their age |
| OAuth 2.0 authorization server (issuing endpoints) | ➖ | A separate product; the `jwt` package covers token signing |
