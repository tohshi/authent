# DPoP resource server

[← authent README](../README.md)

```go
tokens, _ := jwt.NewVerifier(keys, jwt.WithAlgorithms(jwt.ES256), jwt.WithIssuer(iss),
	jwt.WithAudience("api"), jwt.WithExpectedType("at+jwt"),
	jwt.WithConfirmationClaim()) // the binding is checked by dpop.Authenticator
proofs, _ := dpop.NewVerifier(dpop.WithAlgorithms(jwt.ES256),
	dpop.WithReplayCache(jwt.NewMemoryReplayCache())) // or dpop.WithoutReplayCheck()
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

For opaque access tokens, pass an `Introspector` instead of a
`jwt.Verifier`. It asks the authorization server's RFC 7662 introspection
endpoint, authenticating with `client_secret_basic`, and the proof key is
then checked against the response's `cnf.jkt` (RFC 9449 §6.2):
```go
tokens, _ := dpop.NewIntrospector(dpop.IntrospectionConfig{
	Endpoint: "https://as.example.com/introspect",
	ClientID: "api", ClientSecret: secret, Issuer: iss,
	Audiences:         []string{"api"},
	ConfirmationClaim: true, // the binding is checked by dpop.Authenticator
})
auth, _ := dpop.NewAuthenticator(tokens, proofs)
```
`"active": false`, an expired `exp`, a future `nbf`, an `aud` without an
accepted audience, a different `iss` or a non-string `scope` fail with
`dpop.ErrInactiveToken`. A failed request, a redirect, or an unparsable
response, with no boolean `active`, is an error that does not wrap
`authent.ErrUnauthenticated`. The endpoint must be https, redirects are
never followed, and the default client times out after 10 seconds. `iss`
is optional in RFC 7662; set `RequireIssuer` to reject responses without
it.
