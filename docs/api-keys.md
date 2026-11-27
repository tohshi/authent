# API keys

[← authent README](../README.md)

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
