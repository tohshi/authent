// Package oidc is an OpenID Connect relying party for the authorization
// code flow with PKCE (OpenID Connect Core 1.0, RFC 7636).
//
// It is HTTP-framework agnostic: AuthCodeURL returns the URL to redirect to
// and the state, nonce and PKCE verifier that the caller must keep (for
// example in a session) until the callback, where it passes them back to
// Exchange together with the "state" and "code" query parameters.
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
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent"
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
	var userinfo error
	if p.UserinfoEndpoint != "" {
		userinfo = requireHTTPS("userinfo_endpoint", p.UserinfoEndpoint)
	}
	return errors.Join(
		requireHTTPS("issuer", p.Issuer),
		requireHTTPS("authorization_endpoint", p.AuthorizationEndpoint),
		requireHTTPS("token_endpoint", p.TokenEndpoint),
		requireHTTPS("jwks_uri", p.JWKSURI),
		userinfo,
	)
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
	// Algorithms accepted for ID tokens. The default is the asymmetric
	// algorithms the provider advertises, or RS256 if it advertises none.
	Algorithms []jwt.Algorithm
	// HTTPClient is used for the token endpoint, the JWK Set and the
	// UserInfo endpoint. The default is http.DefaultClient.
	HTTPClient *http.Client
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
	verifier          *jwt.Verifier
	client            *http.Client
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

	keys, err := jwt.NewRemoteKeySet(p.JWKSURI, jwt.WithHTTPClient(cfg.HTTPClient), jwt.WithKeySetClock(cfg.Now))
	if err != nil {
		return nil, err
	}
	verifier, err := jwt.NewVerifier(keys,
		jwt.WithAlgorithms(algs...),
		jwt.WithIssuer(p.Issuer),
		jwt.WithAudience(cfg.ClientID),
		jwt.WithLeeway(cfg.Leeway),
		jwt.WithClock(cfg.Now),
	)
	if err != nil {
		return nil, err
	}
	scopes := append([]string{"openid"}, slices.DeleteFunc(slices.Clone(cfg.Scopes), func(s string) bool { return s == "openid" })...)
	authStyle := oauth2.AuthStyleAutoDetect
	if assertionSigner != nil {
		// InParams adds client_id without a client_secret or Basic header.
		// AutoDetect would first try Basic and could resend the same assertion.
		authStyle = oauth2.AuthStyleInParams
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
		client:            cfg.HTTPClient,
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
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthCodeURL starts an authorization request with fresh state, nonce and
// an S256 PKCE challenge. opts may add parameters such as prompt.
func (c *Client) AuthCodeURL(opts ...oauth2.AuthCodeOption) (AuthRequest, error) {
	state, err := randomString()
	if err != nil {
		return AuthRequest{}, err
	}
	nonce, err := randomString()
	if err != nil {
		return AuthRequest{}, err
	}
	verifier := oauth2.GenerateVerifier()
	opts = append([]oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	}, opts...)
	return AuthRequest{
		URL:          c.oauth.AuthCodeURL(state, opts...),
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
	}, nil
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

	opts := []oauth2.AuthCodeOption{oauth2.VerifierOption(req.CodeVerifier)}
	if c.assertionSigner != nil {
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
		opts = append(opts,
			oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
			oauth2.SetAuthURLParam("client_assertion", assertion))
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.client)
	tok, err := c.oauth.Exchange(ctx, code, opts...)
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			return nil, fmt.Errorf("%w: %w", ErrExchangeRejected, err)
		}
		return nil, fmt.Errorf("oidc: token exchange: %w", err)
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
