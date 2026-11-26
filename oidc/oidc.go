// Package oidc is an OpenID Connect relying party for the authorization
// code flow with PKCE (OpenID Connect Core 1.0, RFC 7636), optionally with
// pushed authorization requests (PAR, RFC 9126) and DPoP-bound tokens
// (RFC 9449).
//
// It is HTTP-framework agnostic: AuthCodeURL (or PushAuthCodeURL) returns
// the URL to redirect to and the state, nonce and PKCE verifier that the
// caller must keep (for example in a session) until the callback, where it
// passes them back to Exchange together with the "state" and "code" query
// parameters.
package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/dpop"
	"github.com/tohshi/authent/jwt"
)

var (
	// ErrStateMismatch means the callback's state does not match the
	// request (possible CSRF). It wraps authent.ErrUnauthenticated.
	ErrStateMismatch = fmt.Errorf("oidc: state mismatch: %w", authent.ErrUnauthenticated)
	// ErrExchangeRejected means the provider rejected the code exchange,
	// for example an invalid or reused code or a wrong PKCE verifier.
	ErrExchangeRejected = fmt.Errorf("oidc: code exchange rejected: %w", authent.ErrUnauthenticated)
	// ErrInvalidIDToken means the ID token is missing or fails a check
	// specific to OpenID Connect. Signature and standard claim failures
	// are reported as jwt errors.
	ErrInvalidIDToken = fmt.Errorf("oidc: invalid ID token: %w", authent.ErrUnauthenticated)
	// ErrPushRejected means the provider rejected a pushed authorization
	// request, typically because of the client's configuration (for
	// example an unregistered redirect URI or wrong credentials). No user
	// is involved yet, so it does not wrap authent.ErrUnauthenticated.
	ErrPushRejected = errors.New("oidc: pushed authorization request rejected")
	// ErrPARRequired is returned by AuthCodeURL when the provider
	// requires pushed authorization requests; use PushAuthCodeURL.
	ErrPARRequired = errors.New("oidc: provider requires pushed authorization requests")
)

// Provider is OpenID Provider metadata (OpenID Connect Discovery 1.0).
type Provider struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint,omitempty"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// RFC 9126 §5.
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests bool   `json:"require_pushed_authorization_requests,omitempty"`
	// RFC 9449 §5.1.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

// Discover fetches the provider metadata for issuer. The issuer in the
// metadata must equal issuer exactly, and all endpoints must use https.
// client may be nil to use http.DefaultClient.
func Discover(ctx context.Context, issuer string, client *http.Client) (*Provider, error) {
	if err := requireHTTPS("issuer", issuer); err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: discovery: status %s", resp.Status)
	}
	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	if len(body) > maxBody {
		return nil, errors.New("oidc: discovery document too large")
	}
	var p Provider
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	// OpenID Connect Discovery §4.3: prevents a provider from impersonating
	// another issuer.
	if p.Issuer != issuer {
		return nil, fmt.Errorf("oidc: discovery: issuer %q does not match %q", p.Issuer, issuer)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Provider) validate() error {
	errs := []error{
		requireHTTPS("issuer", p.Issuer),
		requireHTTPS("authorization_endpoint", p.AuthorizationEndpoint),
		requireHTTPS("token_endpoint", p.TokenEndpoint),
		requireHTTPS("jwks_uri", p.JWKSURI),
	}
	if p.UserinfoEndpoint != "" {
		errs = append(errs, requireHTTPS("userinfo_endpoint", p.UserinfoEndpoint))
	}
	if p.PushedAuthorizationRequestEndpoint != "" || p.RequirePushedAuthorizationRequests {
		errs = append(errs, requireHTTPS("pushed_authorization_request_endpoint", p.PushedAuthorizationRequestEndpoint))
	}
	return errors.Join(errs...)
}

func requireHTTPS(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("oidc: %s must be an absolute https URL: %q", name, raw)
	}
	return nil
}

// Config configures a Client.
type Config struct {
	ClientID     string
	ClientSecret string // empty for public clients and private_key_jwt
	// PrivateKeyJWT enables private_key_jwt token endpoint authentication.
	// The provider must have the corresponding public key registered for this client.
	// It cannot be combined with ClientSecret.
	PrivateKeyJWT *PrivateKeyJWTConfig
	RedirectURL   string
	// Scopes requested in addition to "openid".
	Scopes []string
	// Algorithms accepted for ID tokens and signed UserInfo responses.
	// The default is the asymmetric algorithms the provider advertises for
	// ID tokens, or RS256 if it advertises none.
	Algorithms []jwt.Algorithm
	// HTTPClient is used for the token, pushed authorization request,
	// UserInfo and JWK Set endpoints. The default is http.DefaultClient.
	HTTPClient *http.Client
	// AuthStyle selects how the client secret is sent to the token
	// endpoint. The default auto-detects it. Pushed authorization requests
	// use client_secret_post with AuthStyleInParams and
	// client_secret_basic otherwise.
	AuthStyle oauth2.AuthStyle
	// DPoP, if set, binds the issued tokens to the Prover's key
	// (RFC 9449): authorization requests carry its thumbprint in
	// "dpop_jkt" (or, when pushed, a DPoP proof), token requests carry
	// DPoP proofs, and Exchange fails unless the provider issues a
	// DPoP-bound access token. Use HTTPClient to call resource servers
	// with the token.
	DPoP *dpop.Prover
	// Leeway tolerates clock skew when validating ID tokens. The default
	// is 1 minute.
	Leeway time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// PrivateKeyJWTConfig selects the signing key for client authentication.
// PrivateKey is an RSA or ECDSA private key, or an Ed25519 private key,
// matching Algorithm. KeyID is sent in the JWT's kid header when set.
type PrivateKeyJWTConfig struct {
	Algorithm  jwt.Algorithm
	PrivateKey any
	KeyID      string
}

// Client is an OpenID Connect relying party. It is safe for concurrent use.
type Client struct {
	provider          *Provider
	oauth             oauth2.Config
	verifier          *jwt.Verifier // ID tokens
	userinfo          *jwt.Verifier // signed UserInfo responses
	client            *http.Client  // for the token and PAR endpoints; adds DPoP proofs if configured
	singleShot        *http.Client  // client, without the DPoP transport's nonce retry
	base              *http.Client  // Config.HTTPClient
	dpop              *dpop.Prover
	assertionSigner   *jwt.Signer
	assertionAudience string
	now               func() time.Time
}

// NewClient returns a Client for the provider.
func NewClient(p *Provider, cfg Config) (*Client, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc: ClientID and RedirectURL are required")
	}
	var assertionSigner *jwt.Signer
	if cfg.PrivateKeyJWT != nil {
		if cfg.ClientSecret != "" {
			return nil, errors.New("oidc: PrivateKeyJWT and ClientSecret cannot be combined")
		}
		if cfg.PrivateKeyJWT.Algorithm.IsSymmetric() {
			return nil, errors.New("oidc: PrivateKeyJWT requires an asymmetric algorithm")
		}
		if len(p.TokenEndpointAuthMethodsSupported) > 0 && !slices.Contains(p.TokenEndpointAuthMethodsSupported, "private_key_jwt") {
			return nil, errors.New("oidc: provider does not support private_key_jwt")
		}
		if len(p.TokenEndpointAuthSigningAlgValuesSupported) > 0 && !slices.Contains(p.TokenEndpointAuthSigningAlgValuesSupported, string(cfg.PrivateKeyJWT.Algorithm)) {
			return nil, fmt.Errorf("oidc: provider does not support %s for client authentication", cfg.PrivateKeyJWT.Algorithm)
		}
		var err error
		assertionSigner, err = jwt.NewSigner(cfg.PrivateKeyJWT.Algorithm, cfg.PrivateKeyJWT.PrivateKey,
			jwt.WithKeyID(cfg.PrivateKeyJWT.KeyID), jwt.WithType("client-authentication+jwt"))
		if err != nil {
			return nil, fmt.Errorf("oidc: private_key_jwt: %w", err)
		}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	algs := cfg.Algorithms
	if len(algs) == 0 {
		algs = defaultAlgorithms(p.IDTokenSigningAlgValuesSupported)
	}
	if cfg.DPoP != nil && len(p.DPoPSigningAlgValuesSupported) > 0 &&
		!slices.Contains(p.DPoPSigningAlgValuesSupported, string(cfg.DPoP.Algorithm())) {
		return nil, fmt.Errorf("oidc: provider does not support DPoP algorithm %q", cfg.DPoP.Algorithm())
	}

	keys, err := jwt.NewRemoteKeySet(p.JWKSURI, jwt.WithHTTPClient(cfg.HTTPClient), jwt.WithKeySetClock(cfg.Now))
	if err != nil {
		return nil, err
	}
	idTokenOpts := []jwt.VerifierOption{
		jwt.WithAlgorithms(algs...),
		jwt.WithIssuer(p.Issuer),
		jwt.WithAudience(cfg.ClientID),
		jwt.WithLeeway(cfg.Leeway),
		jwt.WithClock(cfg.Now),
		// The ID token is consumed here, never presented as a bearer
		// credential, so a "cnf" claim in it is harmless.
		jwt.WithConfirmationClaim(),
	}
	verifier, err := jwt.NewVerifier(keys, idTokenOpts...)
	if err != nil {
		return nil, err
	}
	userinfo, err := jwt.NewVerifier(keys, append(idTokenOpts,
		jwt.WithOptionalExpiration(), jwt.WithMaxTokenSize(maxUserInfoSize))...)
	if err != nil {
		return nil, err
	}
	scopes := append([]string{"openid"}, slices.DeleteFunc(slices.Clone(cfg.Scopes), func(s string) bool { return s == "openid" })...)
	authStyle := cfg.AuthStyle
	if assertionSigner != nil {
		// InParams adds client_id without a client_secret or Basic header.
		// AutoDetect would first try Basic and could resend the same assertion.
		authStyle = oauth2.AuthStyleInParams
	}
	client, singleShot := cfg.HTTPClient, cfg.HTTPClient
	if cfg.DPoP != nil {
		c := *cfg.HTTPClient
		c.Transport = &dpop.Transport{Prover: cfg.DPoP, Base: cfg.HTTPClient.Transport}
		client = &c
		s := c
		s.Transport = singleUse{c.Transport}
		singleShot = &s
	}
	return &Client{
		provider: p,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:   p.AuthorizationEndpoint,
				TokenURL:  p.TokenEndpoint,
				AuthStyle: authStyle,
			},
		},
		verifier:          verifier,
		userinfo:          userinfo,
		client:            client,
		singleShot:        singleShot,
		base:              cfg.HTTPClient,
		dpop:              cfg.DPoP,
		assertionSigner:   assertionSigner,
		assertionAudience: p.Issuer,
		now:               cfg.Now,
	}, nil
}

// defaultAlgorithms keeps the asymmetric algorithms the provider supports.
// HMAC ID tokens are signed with the client secret and are not accepted by
// default.
func defaultAlgorithms(advertised []string) []jwt.Algorithm {
	asymmetric := []jwt.Algorithm{
		jwt.RS256, jwt.RS384, jwt.RS512, jwt.PS256, jwt.PS384, jwt.PS512,
		jwt.ES256, jwt.ES384, jwt.ES512, jwt.EdDSA,
	}
	var out []jwt.Algorithm
	for _, a := range advertised {
		if alg := jwt.Algorithm(a); slices.Contains(asymmetric, alg) {
			out = append(out, alg)
		}
	}
	if len(out) == 0 {
		out = []jwt.Algorithm{jwt.RS256}
	}
	return out
}

// AuthRequest is an authorization request in flight. Keep State, Nonce and
// CodeVerifier server-side, bound to the user's browser (for example in a
// pre-login session), and never expose CodeVerifier to the client.
type AuthRequest struct {
	URL          string
	State        string
	Nonce        string
	CodeVerifier string
	// Expiry is when the pushed request behind URL expires (RFC 9126
	// §2.2); redirect before then. It is zero for AuthCodeURL.
	Expiry time.Time
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthCodeURL starts an authorization request with fresh state, nonce and
// an S256 PKCE challenge. opts may add parameters such as prompt. It fails
// with ErrPARRequired if the provider requires PushAuthCodeURL.
func (c *Client) AuthCodeURL(opts ...oauth2.AuthCodeOption) (AuthRequest, error) {
	if c.provider.RequirePushedAuthorizationRequests {
		return AuthRequest{}, ErrPARRequired
	}
	if c.dpop != nil {
		// RFC 9449 §10: binds the authorization code to the DPoP key.
		opts = append(slices.Clip(opts), oauth2.SetAuthURLParam("dpop_jkt", c.dpop.Thumbprint()))
	}
	req, opts, err := newAuthRequest(opts)
	if err != nil {
		return AuthRequest{}, err
	}
	req.URL = c.oauth.AuthCodeURL(req.State, opts...)
	return req, nil
}

// newAuthRequest generates state, nonce and PKCE verifier, and returns
// opts extended with the matching parameters.
func newAuthRequest(opts []oauth2.AuthCodeOption) (AuthRequest, []oauth2.AuthCodeOption, error) {
	state, err := randomString()
	if err != nil {
		return AuthRequest{}, nil, err
	}
	nonce, err := randomString()
	if err != nil {
		return AuthRequest{}, nil, err
	}
	verifier := oauth2.GenerateVerifier()
	opts = append([]oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	}, opts...)
	return AuthRequest{State: state, Nonce: nonce, CodeVerifier: verifier}, opts, nil
}

// PushAuthCodeURL is like AuthCodeURL but sends the authorization request
// parameters directly to the provider's pushed authorization request
// endpoint (RFC 9126), authenticated with the client credentials. The
// returned URL carries only client_id and the request_uri reference, so
// the parameters cannot be read or altered in the browser.
//
// With DPoP configured, the request carries a DPoP proof, which binds the
// authorization code to the key (RFC 9449 §10.1).
//
// A rejection by the provider wraps ErrPushRejected.
func (c *Client) PushAuthCodeURL(ctx context.Context, opts ...oauth2.AuthCodeOption) (AuthRequest, error) {
	endpoint := c.provider.PushedAuthorizationRequestEndpoint
	if endpoint == "" {
		return AuthRequest{}, errors.New("oidc: provider has no pushed_authorization_request_endpoint")
	}
	req, opts, err := newAuthRequest(opts)
	if err != nil {
		return AuthRequest{}, err
	}
	params, err := c.authParams(req.State, opts)
	if err != nil {
		return AuthRequest{}, err
	}

	if c.oauth.ClientSecret != "" && c.oauth.Endpoint.AuthStyle == oauth2.AuthStyleInParams {
		params.Set("client_secret", c.oauth.ClientSecret)
	}
	status, body, err := c.push(ctx, endpoint, params)
	if code, _ := oauthError(status, body); err == nil && code == "use_dpop_nonce" && c.assertionSigner != nil && c.dpop != nil {
		// The DPoP transport does not resend a client assertion; retry
		// here with a fresh one and the nonce the provider just supplied.
		status, body, err = c.push(ctx, endpoint, params)
	}
	if err != nil {
		return AuthRequest{}, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		if code, desc := oauthError(status, body); code != "" {
			return AuthRequest{}, fmt.Errorf("%w: %s: %s", ErrPushRejected, code, desc)
		}
		return AuthRequest{}, fmt.Errorf("oidc: pushed authorization request: status %d", status)
	}
	var par struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &par); err != nil {
		return AuthRequest{}, fmt.Errorf("oidc: pushed authorization response: %w", err)
	}
	if par.RequestURI == "" || par.ExpiresIn <= 0 {
		return AuthRequest{}, errors.New("oidc: pushed authorization response lacks request_uri or expires_in")
	}

	// RFC 9126 §4: only client_id and request_uri go to the browser.
	u, err := url.Parse(c.provider.AuthorizationEndpoint)
	if err != nil {
		return AuthRequest{}, err
	}
	q := u.Query()
	q.Set("client_id", c.oauth.ClientID)
	q.Set("request_uri", par.RequestURI)
	u.RawQuery = q.Encode()
	req.URL = u.String()
	req.Expiry = c.now().Add(time.Duration(par.ExpiresIn) * time.Second)
	return req, nil
}

// push sends one pushed authorization request with the client's
// credentials and returns the response status and body.
func (c *Client) push(ctx context.Context, endpoint string, params url.Values) (int, []byte, error) {
	if c.assertionSigner != nil {
		assertion, err := c.clientAssertion()
		if err != nil {
			return 0, nil, err
		}
		params = maps.Clone(params)
		maps.Copy(params, assertion)
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return 0, nil, err
	}
	if c.assertionSigner != nil {
		// A client assertion is single use, so the body must not be
		// replayed by the DPoP transport.
		hr.GetBody = nil
	}
	hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hr.Header.Set("Accept", "application/json")
	if c.oauth.ClientSecret != "" && c.oauth.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		// RFC 6749 §2.3.1: both values are form-encoded first.
		hr.SetBasicAuth(url.QueryEscape(c.oauth.ClientID), url.QueryEscape(c.oauth.ClientSecret))
	}
	resp, err := c.client.Do(hr)
	if err != nil {
		return 0, nil, fmt.Errorf("oidc: pushed authorization request: %w", err)
	}
	defer resp.Body.Close()
	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return 0, nil, fmt.Errorf("oidc: pushed authorization request: %w", err)
	}
	if len(body) > maxBody {
		return 0, nil, errors.New("oidc: pushed authorization response too large")
	}
	return resp.StatusCode, body, nil
}

// oauthError returns the error code and description of an OAuth error
// response (RFC 6749 §5.2), or empty strings for a success or a body that
// is not one.
func oauthError(status int, body []byte) (code, description string) {
	if status < 400 {
		return "", ""
	}
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) != nil {
		return "", ""
	}
	return e.Error, e.Description
}

// clientAssertion returns the private_key_jwt client authentication
// parameters with a freshly signed assertion.
func (c *Client) clientAssertion() (url.Values, error) {
	id, err := randomString()
	if err != nil {
		return nil, fmt.Errorf("oidc: client assertion ID: %w", err)
	}
	now := c.now()
	assertion, err := c.assertionSigner.Sign(jwt.Claims{
		Issuer:    c.oauth.ClientID,
		Subject:   c.oauth.ClientID,
		Audience:  jwt.Audience{c.assertionAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		ID:        id,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: signing client assertion: %w", err)
	}
	return url.Values{
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}, nil
}

// authParams returns the authorization request parameters that
// AuthCodeURL would put in the URL.
func (c *Client) authParams(state string, opts []oauth2.AuthCodeOption) (url.Values, error) {
	// A Config without AuthURL renders just "?" and the parameters. It is
	// built afresh because oauth2.Config must not be copied.
	cfg := oauth2.Config{ClientID: c.oauth.ClientID, RedirectURL: c.oauth.RedirectURL, Scopes: c.oauth.Scopes}
	params, err := url.ParseQuery(strings.TrimPrefix(cfg.AuthCodeURL(state, opts...), "?"))
	if err != nil {
		return nil, err
	}
	// RFC 9126 §2.1.
	if params.Has("request_uri") {
		return nil, errors.New("oidc: request_uri cannot be pushed")
	}
	return params, nil
}

// Result is the outcome of a successful Exchange.
type Result struct {
	Principal  authent.Principal
	IDToken    *jwt.Claims
	RawIDToken string
	// Token holds the access and refresh tokens.
	Token *oauth2.Token
}

// Exchange completes the flow started by req. state and code are the
// query parameters of the callback.
func (c *Client) Exchange(ctx context.Context, req AuthRequest, state, code string) (*Result, error) {
	if req.State == "" || subtle.ConstantTimeCompare([]byte(state), []byte(req.State)) != 1 {
		return nil, ErrStateMismatch
	}
	if code == "" {
		return nil, fmt.Errorf("%w: empty code", ErrExchangeRejected)
	}

	tok, err := c.exchange(ctx, code, req.CodeVerifier)
	var re *oauth2.RetrieveError
	if c.assertionSigner != nil && c.dpop != nil && errors.As(err, &re) && re.ErrorCode == "use_dpop_nonce" {
		// The DPoP transport does not resend a client assertion; retry
		// here with a fresh one and the nonce the provider just supplied.
		tok, err = c.exchange(ctx, code, req.CodeVerifier)
	}
	if err != nil {
		if errors.As(err, &re) {
			return nil, fmt.Errorf("%w: %w", ErrExchangeRejected, err)
		}
		return nil, fmt.Errorf("oidc: token exchange: %w", err)
	}
	if c.dpop != nil && !strings.EqualFold(tok.TokenType, dpop.TokenType) {
		// RFC 9449 §5: without a DPoP token_type the access token is not
		// bound, so the protection asked for is not given. This is a
		// provider or configuration problem, not a failed login.
		return nil, fmt.Errorf("oidc: provider issued a %q access token instead of a DPoP-bound one", tok.TokenType)
	}

	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, fmt.Errorf("%w: missing id_token", ErrInvalidIDToken)
	}
	claims, header, err := c.verifier.VerifyWithHeader(ctx, raw)
	if err != nil {
		return nil, err
	}
	if err := c.checkIDToken(claims, header, req.Nonce, tok.AccessToken); err != nil {
		return nil, err
	}
	p, err := jwt.PrincipalFromClaims(claims, authent.MethodOIDC)
	if err != nil {
		return nil, err
	}
	return &Result{Principal: p, IDToken: claims, RawIDToken: raw, Token: tok}, nil
}

// exchange sends one token request for code.
func (c *Client) exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	opts := []oauth2.AuthCodeOption{oauth2.VerifierOption(verifier)}
	client := c.client
	if c.assertionSigner != nil {
		assertion, err := c.clientAssertion()
		if err != nil {
			return nil, err
		}
		for k := range assertion {
			opts = append(opts, oauth2.SetAuthURLParam(k, assertion.Get(k)))
		}
		client = c.singleShot
	}
	return c.oauth.Exchange(context.WithValue(ctx, oauth2.HTTPClient, client), code, opts...)
}

// singleUse stops the DPoP transport from replaying a request body that
// carries a single-use client assertion.
type singleUse struct{ base http.RoundTripper }

func (t singleUse) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.GetBody = nil
	return t.base.RoundTrip(r)
}

// HTTPClient returns a client that sends tok's access token with every
// request and refreshes it with the refresh token when it expires. With
// DPoP configured, the token is sent with the DPoP scheme and every
// request, including refreshes, carries a proof. Requests use the
// transport of Config.HTTPClient; ctx is used for refreshes.
//
// Refreshed ID tokens are not verified. With PrivateKeyJWT the token is
// not refreshed, because x/oauth2 cannot add a client assertion.
func (c *Client) HTTPClient(ctx context.Context, tok *oauth2.Token) *http.Client {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.client)
	src := c.oauth.TokenSource(ctx, tok)
	hc := *c.base
	if c.dpop != nil {
		hc.Transport = &dpop.Transport{Prover: c.dpop, Source: src, Base: c.base.Transport}
	} else {
		hc.Transport = &oauth2.Transport{Source: src, Base: c.base.Transport}
	}
	return &hc
}

// checkIDToken applies the ID token checks of OpenID Connect Core §3.1.3.7
// that go beyond generic JWT validation.
func (c *Client) checkIDToken(claims *jwt.Claims, header jwt.Header, nonce, accessToken string) error {
	got, _ := claims.Extra["nonce"].(string)
	if nonce == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return fmt.Errorf("%w: nonce mismatch", ErrInvalidIDToken)
	}
	azp, hasAzp := claims.Extra["azp"].(string)
	if len(claims.Audience) > 1 && !hasAzp {
		return fmt.Errorf("%w: azp required with multiple audiences", ErrInvalidIDToken)
	}
	if hasAzp && azp != c.oauth.ClientID {
		return fmt.Errorf("%w: azp %q", ErrInvalidIDToken, azp)
	}
	if atHash, ok := claims.Extra["at_hash"].(string); ok {
		want, err := leftHalfHash(header.Algorithm, accessToken)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidIDToken, err)
		}
		if subtle.ConstantTimeCompare([]byte(atHash), []byte(want)) != 1 {
			return fmt.Errorf("%w: at_hash mismatch", ErrInvalidIDToken)
		}
	}
	return nil
}

// leftHalfHash computes at_hash: the base64url encoding of the left half
// of the hash of value, using the hash of the ID token's algorithm (SHA-512
// for EdDSA with Ed25519).
func leftHalfHash(alg jwt.Algorithm, value string) (string, error) {
	h := alg.Hash()
	if alg == jwt.EdDSA {
		h = crypto.SHA512
	}
	if h == 0 || !h.Available() {
		return "", fmt.Errorf("no hash for alg %q", alg)
	}
	hh := h.New()
	hh.Write([]byte(value))
	sum := hh.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}
