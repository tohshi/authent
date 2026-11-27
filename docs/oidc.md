# OIDC

[← authent README](../README.md)

```go
prov, _ := oidc.Discover(ctx, "https://accounts.example.com", nil)
client, _ := oidc.NewClient(prov, oidc.Config{ClientID: id, ClientSecret: secret, RedirectURL: cb})

req, _ := client.AuthCodeURL() // store all of req server-side, bound to the browser
// ... redirect to req.URL and receive the callback ...
res, err := client.Exchange(ctx, req, r.URL.Query().Get("state"), r.URL.Query().Get("code"))

info, err := client.UserInfo(ctx, res.Token, res.Principal.Subject) // optional
```
For `private_key_jwt`, register the corresponding public key with the provider
and configure an asymmetric signing key instead of `ClientSecret`:
```go
client, _ := oidc.NewClient(prov, oidc.Config{
	ClientID: id, RedirectURL: cb,
	PrivateKeyJWT: &oidc.PrivateKeyJWTConfig{
		Algorithm: jwt.ES256, PrivateKey: privateKey, KeyID: "client-key-1",
	},
})
```
Each token exchange signs a fresh, five-minute client assertion. Its audience
is the provider issuer, as required by RFC 10070.

`Exchange` checks:
- the state and nonce
- PKCE (S256)
- the ID token's signature, `iss`, `aud` and `exp`
- `azp`
- `at_hash`
- `auth_time` and `acr`, when the request asked for them:
```go
req, _ := client.AuthCodeURL(
	oauth2.SetAuthURLParam("max_age", "300"),
	oauth2.SetAuthURLParam("acr_values", "urn:example:mfa"))
```
  With `max_age`, the ID token must carry an `auth_time` at most that many
  seconds old, plus `Config.Leeway`, so `max_age=0` still accepts an
  authentication within the leeway. With `acr_values`, its `acr` must be
  one of the requested values, as for an essential claim. Both are kept in
  the `AuthRequest`, so store all of it: `Exchange` fails with
  `ErrAuthRequestMismatch` rather than skip the checks if `MaxAge` or
  `ACRValues` are lost. An `AuthRequest` with `MaxAge` or `ACRValues`
  created by an earlier version of this package has no such binding in
  its nonce, so a login in flight during an upgrade fails closed.

`UserInfo` calls the provider's UserInfo endpoint with the access token and
rejects the response unless its `sub` exactly matches the ID token's. A
signed response (`application/jwt`) must also verify with the provider's
keys and carry the provider as `iss` and the client in `aud`; it needs no
`exp`. With `Config.RequireSignedUserInfo`, plain JSON responses are
rejected. Encrypted responses are always rejected. Redirects are not
followed, so the access token is never sent anywhere but the advertised
https endpoint.

`Refresh` uses a `Result`'s refresh token and returns the next `Result`:
```go
res, err = client.Refresh(ctx, res) // store res again: the refresh token may have rotated
```
It authenticates the client as `Exchange` does, including with
`private_key_jwt`, and sends DPoP proofs when configured. A new ID token
must verify like the first one and describe the same authentication: the
same `iss`, `sub`, `aud` and `azp`, and the same `auth_time` and `nonce`
when it has them. A rejected refresh token wraps `oidc.ErrRefreshRejected`.

Logout works in both directions:
```go
// RP-initiated: end the local session, then log out at the provider.
u, _ := client.EndSessionURL(oidc.EndSession{
	IDTokenHint: res.RawIDToken, PostLogoutRedirectURI: "https://app.example/bye", State: state,
})

// Front-channel: GET on the frontchannel_logout_uri.
l, err := client.FrontChannelLogout(r.URL.Query())

// Back-channel: POST on the backchannel_logout_uri.
r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
	// reply 400
}
l, err := client.BackChannelLogout(ctx, r.PostFormValue("logout_token"))
// end every local session whose ID token l.Matches; reply 200, or 400 on error
```
- Front-channel requests must carry the provider's `iss` and a `sid`, so
  register the client with `frontchannel_logout_session_required`.
- Logout tokens are verified like ID tokens. They must also be typed
  `logout+jwt`, carry the back-channel logout event and a `sub` or `sid`,
  have no `nonce`, and be at most two minutes old. Each `jti` is accepted
  once through `Config.ReplayCache` (in memory by default; use a shared
  cache such as `jwt/sqlreplay` behind a load balancer).
- Respond to both with `Cache-Control: no-store`.

Pushed authorization requests (RFC 9126) send the parameters to the
provider over the back channel, so the browser only sees a `request_uri`:
```go
req, err := client.PushAuthCodeURL(ctx) // redirect to req.URL before req.Expiry
```
`AuthCodeURL` returns `oidc.ErrPARRequired` when the provider sets
`require_pushed_authorization_requests`. The client authenticates at the PAR
endpoint as at the token endpoint, with its secret or `private_key_jwt`.

With `Config.JAR` set, authorization requests are signed request objects
(RFC 9101), so their parameters cannot be altered on the way:
```go
client, _ := oidc.NewClient(prov, oidc.Config{ /* ... */ PrivateKeyJWT: &oidc.PrivateKeyJWTConfig{ /* ... */ }, JAR: true})
req, _ := client.AuthCodeURL()          // URL carries client_id, response_type, scope and request
req, _ = client.PushAuthCodeURL(ctx)    // the pushed form carries only client_id, request and the client assertion
```
- The object is signed with the `private_key_jwt` key and typed
  `oauth-authz-req+jwt`. It carries every authorization parameter plus
  `iss` (the client), `aud` (the issuer), `iat`, `nbf`, a five-minute `exp`
  and a random `jti`; `req.Expiry` says when a by-value URL stops working.
- `NewClient` fails if the provider sets `require_signed_request_object`
  without `JAR`, or does not list the key's algorithm in
  `request_object_signing_alg_values_supported`.

With `Config.DPoP` set, tokens are bound to the client's key (RFC 9449):
```go
prover, _ := dpop.NewProver(jwt.ES256, key) // keep key as long as the tokens
client, _ := oidc.NewClient(prov, oidc.Config{ /* ... */ DPoP: prover})
res, err := client.Exchange(ctx, req, state, code)
api := client.HTTPClient(ctx, res.Token) // sends "Authorization: DPoP" with a proof per request
```
- The authorization code is bound to the key: through `dpop_jkt`, or a DPoP
  proof on the pushed request.
- Token requests and refreshes carry proofs. `Exchange` fails unless the
  provider issues a `DPoP` token, rather than silently falling back to
  Bearer.
- Server-provided nonces are remembered per origin, and a request rejected
  with `use_dpop_nonce` is retried once with the new nonce. With
  `private_key_jwt`, the retry carries a freshly signed client assertion.
- `UserInfo` sends a DPoP token with the DPoP scheme and a proof.
