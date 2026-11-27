# Passwords

[← authent README](../README.md)

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
