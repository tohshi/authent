# HTTP middleware

[← authent README](../README.md)

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

## gRPC
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
