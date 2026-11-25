package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/dpop"
	"github.com/tohshi/authent/jwt"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

const (
	clientID     = "client-1"
	clientSecret = "secret-1"
	redirectURL  = "https://app.example/callback"
)

type grant struct {
	challenge string
	nonce     string
	jkt       string // DPoP key the code is bound to
}

// fakeProvider is a minimal OpenID Provider.
type fakeProvider struct {
	*httptest.Server
	signer *jwt.Signer

	mu     sync.Mutex
	grants map[string]grant // code -> grant
	// mutate customizes ID token claims per test.
	mutate      func(c *jwt.Claims)
	omitIDToken bool
	issuer      string // advertised issuer; defaults to the server URL
	// userinfoEndpoint overrides the advertised userinfo_endpoint; "-"
	// omits it.
	userinfoEndpoint string
	accessTokens     map[string]bool // issued access tokens
	// userinfo overrides the UserInfo response for a valid access token.
	userinfo          func(w http.ResponseWriter, r *http.Request)
	authMethods       []string
	authAlgs          []string
	assertionVerifier *jwt.Verifier
	assertions        []jwt.Claims

	// PAR (RFC 9126)
	par        bool // advertise the PAR endpoint
	requirePAR bool
	pushed     map[string]url.Values // request_uri -> parameters
	lastPush   *http.Request

	// DPoP (RFC 9449)
	dpopAlgs   []string
	proofs     *dpop.Verifier
	dpopNonce  string // if set, required in every proof
	bearerOnly bool   // ignore DPoP proofs, as a provider without DPoP support would
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, err := jwt.NewSigner(jwt.ES256, key, jwt.WithKeyID("k1"))
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := dpop.NewVerifier(dpop.WithAlgorithms(jwt.ES256), dpop.WithReplayCache(dpop.NewMemoryReplayCache()),
		dpop.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{signer: signer, grants: map[string]grant{}, accessTokens: map[string]bool{},
		pushed: map[string]url.Values{}, proofs: proofs}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := p.issuer
		if iss == "" {
			iss = p.URL
		}
		userinfo := p.userinfoEndpoint
		switch userinfo {
		case "":
			userinfo = p.URL + "/userinfo"
		case "-":
			userinfo = ""
		}
		meta := Provider{
			Issuer:                            iss,
			AuthorizationEndpoint:             p.URL + "/authorize",
			TokenEndpoint:                     p.URL + "/token",
			JWKSURI:                           p.URL + "/jwks",
			UserinfoEndpoint:                  userinfo,
			IDTokenSigningAlgValuesSupported:  []string{"ES256", "HS256"},
			TokenEndpointAuthMethodsSupported: p.authMethods,
			TokenEndpointAuthSigningAlgValuesSupported: p.authAlgs,
			RequirePushedAuthorizationRequests:         p.requirePAR,
			DPoPSigningAlgValuesSupported:              p.dpopAlgs,
		}
		if p.par || p.requirePAR {
			meta.PushedAuthorizationRequestEndpoint = p.URL + "/par"
		}
		_ = json.MarshalWrite(w, meta)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.MarshalWrite(w, jwt.JWKSet{Keys: []jwt.JWK{p.signer.VerificationKey()}})
	})
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /userinfo", p.userinfoHandler)
	mux.HandleFunc("POST /par", p.pushAuthorization)
	mux.HandleFunc("GET /api", p.api)
	p.Server = httptest.NewTLSServer(mux)
	t.Cleanup(p.Close)
	return p
}

// authorize simulates the user approving the request at authURL and
// returns the code the provider would send to the redirect URI.
func (p *fakeProvider) authorize(t *testing.T, authURL string) (state, code string) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if ru := q.Get("request_uri"); ru != "" {
		if len(q) != 2 || q.Get("client_id") != clientID {
			t.Fatalf("pushed authorization URL carries parameters: %v", q)
		}
		p.mu.Lock()
		q = p.pushed[ru]
		delete(p.pushed, ru) // request URIs are single use
		p.mu.Unlock()
		if q == nil {
			t.Fatalf("unknown request_uri %q", ru)
		}
	} else if p.requirePAR {
		t.Fatal("authorization request was not pushed")
	}
	if q.Get("client_id") != clientID || q.Get("redirect_uri") != redirectURL ||
		q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("bad authorization request: %v", q)
	}
	if q.Get("scope") != "openid email" {
		t.Fatalf("scope = %q", q.Get("scope"))
	}
	code = "code-" + q.Get("state")[:8]
	p.mu.Lock()
	p.grants[code] = grant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), jkt: q.Get("dpop_jkt")}
	p.mu.Unlock()
	return q.Get("state"), code
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	tokenError := func() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}
	if err := r.ParseForm(); err != nil {
		tokenError()
		return
	}
	if !p.clientAuthenticated(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// The proof is checked before the code is looked up, so that a
	// request rejected for a missing nonce does not consume the code.
	var jkt string
	if r.Header.Get(dpop.HeaderName) != "" && !p.bearerOnly {
		proof, err := p.checkProof(r, "")
		if err != nil {
			p.dpopError(w, err)
			return
		}
		jkt = proof.JKT
	}
	p.mu.Lock()
	g, ok := p.grants[r.PostForm.Get("code")]
	delete(p.grants, r.PostForm.Get("code")) // codes are single use
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge || g.jkt != "" && g.jkt != jkt {
		tokenError()
		return
	}

	accessToken := "access-" + r.PostForm.Get("code")
	p.mu.Lock()
	p.accessTokens[accessToken] = true
	p.mu.Unlock()
	atSum := sha256.Sum256([]byte(accessToken))
	claims := jwt.Claims{
		Issuer:    p.URL,
		Subject:   "user-42",
		Audience:  jwt.Audience{clientID},
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
		Extra: map[string]any{
			"nonce":   g.nonce,
			"email":   "user42@example.com",
			"at_hash": base64.RawURLEncoding.EncodeToString(atSum[:16]),
		},
	}
	if p.mutate != nil {
		p.mutate(&claims)
	}
	idToken, err := p.signer.Sign(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tokenType := "Bearer"
	if jkt != "" {
		tokenType = "DPoP"
	}
	resp := map[string]any{"access_token": accessToken, "token_type": tokenType, "expires_in": 300}
	if !p.omitIDToken {
		resp["id_token"] = idToken
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.MarshalWrite(w, resp)
}

func newClient(t *testing.T, p *fakeProvider, mods ...func(*Config)) *Client {
	t.Helper()
	ctx := context.Background()
	meta, err := Discover(ctx, p.URL, p.Client())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"email", "openid"},
		HTTPClient:   p.Client(),
		Now:          func() time.Time { return now },
	}
	for _, mod := range mods {
		mod(&cfg)
	}
	c, err := NewClient(meta, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFlow(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p)
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatal(err)
	}
	state, code := p.authorize(t, req.URL)
	res, err := c.Exchange(context.Background(), req, state, code)
	if err != nil {
		t.Fatalf("Exchange = %v", err)
	}
	if res.Principal.Subject != "user-42" || res.Principal.Issuer != p.URL || res.Principal.Method != authent.MethodOIDC {
		t.Fatalf("principal = %+v", res.Principal)
	}
	if res.Principal.Claims["email"] != "user42@example.com" || res.Token.AccessToken == "" {
		t.Fatalf("result = %+v", res)
	}
}

func TestPrivateKeyJWTFlow(t *testing.T) {
	p := newFakeProvider(t)
	p.authMethods = []string{"client_secret_basic", "private_key_jwt"}
	p.authAlgs = []string{"ES256"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner(jwt.ES256, key, jwt.WithKeyID("client-key"))
	if err != nil {
		t.Fatal(err)
	}
	p.assertionVerifier, err = jwt.NewVerifier(jwt.NewStaticKeySet(signer.VerificationKey()),
		jwt.WithAlgorithms(jwt.ES256), jwt.WithIssuer(clientID), jwt.WithAudience(p.URL),
		jwt.WithExpectedType("client-authentication+jwt"), jwt.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := Discover(context.Background(), p.URL, p.Client())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(meta, Config{
		ClientID: clientID, RedirectURL: redirectURL, Scopes: []string{"email"},
		PrivateKeyJWT: &PrivateKeyJWTConfig{Algorithm: jwt.ES256, PrivateKey: key, KeyID: "client-key"},
		HTTPClient:    p.Client(), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		req, err := c.AuthCodeURL()
		if err != nil {
			t.Fatal(err)
		}
		state, code := p.authorize(t, req.URL)
		res, err := c.Exchange(context.Background(), req, state, code)
		if err != nil {
			t.Fatal(err)
		}
		if res.Principal.Subject != "user-42" {
			t.Fatalf("principal = %+v", res.Principal)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.assertions) != 2 || p.assertions[0].ID == p.assertions[1].ID ||
		len(p.assertions[0].Audience) != 1 || p.assertions[0].Audience[0] != p.URL {
		t.Fatalf("assertions = %+v", p.assertions)
	}
}

func TestPrivateKeyJWTConfigValidation(t *testing.T) {
	p := newFakeProvider(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	meta := &Provider{Issuer: p.URL, AuthorizationEndpoint: p.URL + "/authorize",
		TokenEndpoint: p.URL + "/token", JWKSURI: p.URL + "/jwks"}
	base := Config{ClientID: clientID, RedirectURL: redirectURL,
		PrivateKeyJWT: &PrivateKeyJWTConfig{Algorithm: jwt.ES256, PrivateKey: key}}
	for _, tc := range []struct {
		name   string
		change func(*Provider, *Config)
	}{
		{"secret and key", func(_ *Provider, c *Config) { c.ClientSecret = clientSecret }},
		{"symmetric algorithm", func(_ *Provider, c *Config) {
			c.PrivateKeyJWT = &PrivateKeyJWTConfig{Algorithm: jwt.HS256, PrivateKey: make([]byte, 32)}
		}},
		{"wrong key", func(_ *Provider, c *Config) {
			c.PrivateKeyJWT = &PrivateKeyJWTConfig{Algorithm: jwt.RS256, PrivateKey: key}
		}},
		{"unsupported method", func(p *Provider, _ *Config) {
			p.TokenEndpointAuthMethodsSupported = []string{"client_secret_basic"}
		}},
		{"unsupported algorithm", func(p *Provider, _ *Config) {
			p.TokenEndpointAuthSigningAlgValuesSupported = []string{"RS256"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, cfg := *meta, base
			tc.change(&provider, &cfg)
			if _, err := NewClient(&provider, cfg); err == nil {
				t.Fatal("NewClient accepted invalid private_key_jwt configuration")
			}
		})
	}
}

func TestAuthCodeURLIsFresh(t *testing.T) {
	c := newClient(t, newFakeProvider(t))
	a, _ := c.AuthCodeURL()
	b, _ := c.AuthCodeURL()
	if a.State == b.State || a.Nonce == b.Nonce || a.CodeVerifier == b.CodeVerifier {
		t.Fatal("state, nonce or verifier reused")
	}
	u, _ := url.Parse(a.URL)
	if u.Query().Has("code_verifier") {
		t.Fatal("verifier leaked into the authorization URL")
	}
}

func TestExchangeRejections(t *testing.T) {
	ctx := context.Background()
	type tc struct {
		name  string
		setup func(p *fakeProvider, req *AuthRequest, state, code *string)
		want  error
	}
	for _, tc := range []tc{
		{"state mismatch", func(_ *fakeProvider, _ *AuthRequest, state, _ *string) { *state = "forged" }, ErrStateMismatch},
		{"empty stored state", func(_ *fakeProvider, req *AuthRequest, state, _ *string) { req.State, *state = "", "" }, ErrStateMismatch},
		{"wrong verifier", func(_ *fakeProvider, req *AuthRequest, _, _ *string) {
			req.CodeVerifier = "wrong-verifier-wrong-verifier-wrong-verifier"
		}, ErrExchangeRejected},
		{"unknown code", func(_ *fakeProvider, _ *AuthRequest, _, code *string) { *code = "nope" }, ErrExchangeRejected},
		{"nonce mismatch", func(_ *fakeProvider, req *AuthRequest, _, _ *string) { req.Nonce = "other" }, ErrInvalidIDToken},
		{"missing id_token", func(p *fakeProvider, _ *AuthRequest, _, _ *string) { p.omitIDToken = true }, ErrInvalidIDToken},
		{"wrong audience", func(p *fakeProvider, _ *AuthRequest, _, _ *string) {
			p.mutate = func(c *jwt.Claims) { c.Audience = jwt.Audience{"other-client"} }
		}, jwt.ErrInvalidAudience},
		{"multiple audiences without azp", func(p *fakeProvider, _ *AuthRequest, _, _ *string) {
			p.mutate = func(c *jwt.Claims) { c.Audience = jwt.Audience{clientID, "other"} }
		}, ErrInvalidIDToken},
		{"foreign azp", func(p *fakeProvider, _ *AuthRequest, _, _ *string) {
			p.mutate = func(c *jwt.Claims) { c.Extra["azp"] = "other" }
		}, ErrInvalidIDToken},
		{"at_hash mismatch", func(p *fakeProvider, _ *AuthRequest, _, _ *string) {
			p.mutate = func(c *jwt.Claims) { c.Extra["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA" }
		}, ErrInvalidIDToken},
		{"wrong issuer", func(p *fakeProvider, _ *AuthRequest, _, _ *string) {
			p.mutate = func(c *jwt.Claims) { c.Issuer = "https://evil.example" }
		}, jwt.ErrInvalidIssuer},
		{"expired", func(p *fakeProvider, _ *AuthRequest, _, _ *string) {
			p.mutate = func(c *jwt.Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-2 * time.Minute)) }
		}, jwt.ErrExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t)
			c := newClient(t, p)
			req, _ := c.AuthCodeURL()
			state, code := p.authorize(t, req.URL)
			tc.setup(p, &req, &state, &code)
			_, err := c.Exchange(ctx, req, state, code)
			if !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p)
	req, _ := c.AuthCodeURL()
	state, code := p.authorize(t, req.URL)
	if _, err := c.Exchange(context.Background(), req, state, code); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exchange(context.Background(), req, state, code); !errors.Is(err, ErrExchangeRejected) {
		t.Fatalf("replay err = %v", err)
	}
}

func TestDiscoverRejectsIssuerMismatch(t *testing.T) {
	p := newFakeProvider(t)
	p.issuer = "https://evil.example"
	if _, err := Discover(context.Background(), p.URL, p.Client()); err == nil {
		t.Fatal("issuer mismatch accepted")
	}
	if _, err := Discover(context.Background(), "http://insecure.example", nil); err == nil {
		t.Fatal("http issuer accepted")
	}
}

func TestDefaultAlgorithmsExcludeHMAC(t *testing.T) {
	got := defaultAlgorithms([]string{"HS256", "RS256", "none", "ES256"})
	if len(got) != 2 || got[0] != jwt.RS256 || got[1] != jwt.ES256 {
		t.Fatalf("got %v", got)
	}
	if got := defaultAlgorithms(nil); len(got) != 1 || got[0] != jwt.RS256 {
		t.Fatalf("default = %v", got)
	}
}

func TestLeftHalfHash(t *testing.T) {
	// OpenID Connect Core §A.3: access token and at_hash for RS256.
	got, err := leftHalfHash(jwt.RS256, "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y")
	if err != nil {
		t.Fatal(err)
	}
	if want := "77QmUPtjPfzWtF2AnpK9RQ"; got != want {
		t.Fatalf("at_hash = %s, want %s", got, want)
	}
}
