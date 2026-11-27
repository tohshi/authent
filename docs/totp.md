# TOTP

[← authent README](../README.md)

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
