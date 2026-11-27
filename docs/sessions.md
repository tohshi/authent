# Sessions

[← authent README](../README.md)

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

## Persistent session storage
```go
import _ "github.com/jackc/pgx/v5/stdlib" // or any database/sql driver
import "github.com/tohshi/authent/session/sqlstore"

db, _ := sql.Open("pgx", dsn)
store, _ := sqlstore.New(db, sqlstore.PostgreSQL) // also sqlstore.MySQL, sqlstore.SQLite
store.CreateTable(ctx) // or apply store.CreateTableStatements() with your migration tool
m, _ := session.NewManager(store)
// periodically: store.DeleteExpired(ctx)
```
- `sqlstore.Store` works through `database/sql` and imports no driver; you
  choose one.
- Each session is one row keyed by the token hash, with an expiry column.
  `Load` and `List` ignore expired rows, and `DeleteExpired` removes them.
  The Manager still enforces the timeouts itself.
- Versions are compared in each write's `WHERE` clause, so concurrent saves
  are detected. On PostgreSQL, `RevokeAll` briefly locks the sessions table
  against writes to include rotations already in progress; other writes wait
  for it to commit.
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
