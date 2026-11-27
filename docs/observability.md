# Observability

[← authent README](../README.md)

```go
obs := authent.SlogObserver(slog.Default())
auth, _ := password.NewAuthenticator(store, hasher, password.WithObserver(obs))
verifier, _ := jwt.NewVerifier(keys, jwt.WithAlgorithms(jwt.ES256), jwt.WithIssuer(iss),
	jwt.WithAudience("api"), jwt.WithObserver(obs))
engine, _ := rebac.NewEngine(schema, tuples, rebac.WithObserver(obs))
// level=WARN msg=authent kind=authentication method=jwt outcome=rejected reason=expired duration=41µs
```
- Every authenticator, `jwt.Verifier`, `oidc.Config.Observer`,
  `rebac.Engine` and the `httpauth` middleware take an `authent.Observer`.
  It receives one `authent.Event` per decision: its `Kind`
  (authentication, token verification, authorization, HTTP request),
  `Method`, `Outcome` (success, rejected, error), a `Reason` such as
  `expired`, `replayed`, `bad_signature` or `unknown_user`, the `Subject`
  on success and the `Duration`. Authorization checks add the object type,
  the permission, the `Decision` (allowed, denied, conditional) and the
  number of evaluations.
- Events never contain passwords, tokens, codes, keys, session handles,
  CSRF tokens, their hashes, or caveat context values. A password login
  for an unknown user has the reason `unknown_user`, but the error
  returned to the caller stays `password.ErrInvalidCredentials`.
- For metrics, count Events by `Kind`, `Method`, `Outcome` and `Reason`
  and record `Duration` in a histogram: all four have a small, fixed set
  of values. Leave `Subject` out of labels. For tracing, record a span
  that ends when `Observe` is called and started `Duration` earlier, as a
  child of the span in the context.
- `Observe` runs synchronously after the result is decided, so it cannot
  change it. A panic in it is recovered and discarded. It must return
  quickly; hand slow exports to another goroutine. It may be called from
  many goroutines at once, so it must be safe for concurrent use. Without
  an Observer, nothing is measured.
- Not observed: registration and enrollment, and `dpop.Verifier` and
  `dpop.Introspector` when called on their own. `dpop.Authenticator`
  reports the whole check, including the proof and the introspection.
