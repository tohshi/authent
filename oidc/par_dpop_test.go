package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/dpop"
	"github.com/tohshi/authent/jwt"
)

// clientAuthenticated checks client_secret_basic, client_secret_post or,
// when assertionVerifier is set, private_key_jwt. Like a real provider it
// accepts each client assertion only once.
func (p *fakeProvider) clientAuthenticated(r *http.Request) bool {
	if p.assertionVerifier != nil {
		_, _, basic := r.BasicAuth()
		if basic || r.PostForm.Get("client_id") != clientID || r.PostForm.Has("client_secret") ||
			r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
			len(r.PostForm["client_assertion"]) != 1 {
			return false
		}
		claims, err := p.assertionVerifier.Verify(r.Context(), r.PostForm.Get("client_assertion"))
		if err != nil || claims.Subject != clientID || claims.ID == "" ||
			claims.IssuedAt.Time != now || claims.ExpiresAt.Time != now.Add(5*time.Minute) {
			return false
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, seen := range p.assertions {
			if seen.ID == claims.ID {
				return false
			}
		}
		p.assertions = append(p.assertions, *claims)
		return true
	}
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	return id == clientID && secret == clientSecret
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, map[string]string{"error": code, "error_description": "rejected by the test provider"})
}

// pushAuthorization is the PAR endpoint (RFC 9126 §2).
func (p *fakeProvider) pushAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	p.mu.Lock()
	p.lastPush = r
	p.mu.Unlock()
	if !p.clientAuthenticated(r) {
		writeError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Has("request_uri") || r.PostForm.Get("redirect_uri") != redirectURL {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	params := maps.Clone(r.PostForm)
	params.Del("client_secret")
	// RFC 9449 §10.1: a proof on the PAR request binds the code like
	// dpop_jkt does.
	if r.Header.Get(dpop.HeaderName) != "" {
		proof, err := p.checkProof(r, "")
		if err != nil {
			p.dpopError(w, err)
			return
		}
		if jkt := params.Get("dpop_jkt"); jkt != "" && jkt != proof.JKT {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		params.Set("dpop_jkt", proof.JKT)
	}
	ref, _ := randomString()
	uri := "urn:ietf:params:oauth:request_uri:" + ref
	p.mu.Lock()
	p.pushed[uri] = params
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.MarshalWrite(w, map[string]any{"request_uri": uri, "expires_in": 60})
}

func (p *fakeProvider) checkProof(r *http.Request, accessToken string) (*dpop.Proof, error) {
	proof, err := p.proofs.Verify(r.Context(), dpop.Request{
		Method: r.Method, URL: p.URL + r.URL.Path, Proofs: r.Header.Values(dpop.HeaderName), AccessToken: accessToken,
	})
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	want := p.dpopNonce
	p.mu.Unlock()
	if want != "" && proof.Nonce != want {
		return nil, dpop.ErrUseNonce
	}
	return proof, nil
}

func (p *fakeProvider) dpopError(w http.ResponseWriter, err error) {
	if errors.Is(err, dpop.ErrUseNonce) {
		p.mu.Lock()
		w.Header().Set(dpop.NonceHeaderName, p.dpopNonce)
		p.mu.Unlock()
		writeError(w, http.StatusBadRequest, "use_dpop_nonce")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid_dpop_proof")
}

// api is a protected resource that accepts DPoP and Bearer tokens.
func (p *fakeProvider) api(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if tok, err := dpop.AccessToken(authz); err == nil {
		if _, err := p.checkProof(r, tok); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "dpop:"+tok)
		return
	}
	if tok, ok := strings.CutPrefix(authz, "Bearer "); ok {
		_, _ = io.WriteString(w, "bearer:"+tok)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func newProver(t *testing.T) *dpop.Prover {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p, err := dpop.NewProver(jwt.ES256, key, dpop.WithProverClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func withDPoP(p *dpop.Prover) func(*Config) { return func(c *Config) { c.DPoP = p } }

func TestPushedAuthorizationFlow(t *testing.T) {
	ctx := context.Background()
	for name, style := range map[string]oauth2.AuthStyle{
		"client_secret_basic": oauth2.AuthStyleAutoDetect,
		"client_secret_post":  oauth2.AuthStyleInParams,
	} {
		t.Run(name, func(t *testing.T) {
			p := newFakeProvider(t)
			p.requirePAR = true
			c := newClient(t, p, func(c *Config) { c.AuthStyle = style })

			if _, err := c.AuthCodeURL(); !errors.Is(err, ErrPARRequired) {
				t.Fatalf("AuthCodeURL err = %v", err)
			}
			req, err := c.PushAuthCodeURL(ctx, oauth2.SetAuthURLParam("prompt", "login"))
			if err != nil {
				t.Fatalf("PushAuthCodeURL = %v", err)
			}
			if !req.Expiry.Equal(now.Add(time.Minute)) {
				t.Fatalf("Expiry = %v", req.Expiry)
			}
			push := p.lastPush
			_, _, basic := push.BasicAuth()
			if basic == (style == oauth2.AuthStyleInParams) || push.PostForm.Get("prompt") != "login" ||
				push.PostForm.Get("code_challenge") == "" || push.PostForm.Has("code_verifier") {
				t.Fatalf("pushed request: basic=%v form=%v", basic, push.PostForm)
			}
			state, code := p.authorize(t, req.URL)
			if _, err := c.Exchange(ctx, req, state, code); err != nil {
				t.Fatalf("Exchange = %v", err)
			}
		})
	}
}

func TestPushedAuthorizationRejected(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.par = true
	c := newClient(t, p, func(c *Config) { c.RedirectURL = "https://evil.example/callback" })
	_, err := c.PushAuthCodeURL(ctx)
	if !errors.Is(err, ErrPushRejected) || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("err = %v", err)
	}
	c = newClient(t, p, func(c *Config) { c.ClientSecret = "wrong" })
	if _, err := c.PushAuthCodeURL(ctx); !errors.Is(err, ErrPushRejected) {
		t.Fatalf("wrong secret: err = %v", err)
	}
	if _, err := c.PushAuthCodeURL(ctx, oauth2.SetAuthURLParam("request_uri", "urn:x")); err == nil {
		t.Fatal("request_uri pushed")
	}

	c = newClient(t, newFakeProvider(t))
	if _, err := c.PushAuthCodeURL(ctx); err == nil {
		t.Fatal("PushAuthCodeURL without a PAR endpoint succeeded")
	}
}

func TestDiscoverRejectsInsecurePAREndpoint(t *testing.T) {
	meta := Provider{
		Issuer: "https://op.example", AuthorizationEndpoint: "https://op.example/a",
		TokenEndpoint: "https://op.example/t", JWKSURI: "https://op.example/j",
		PushedAuthorizationRequestEndpoint: "http://op.example/par",
	}
	if err := meta.validate(); err == nil {
		t.Fatal("http PAR endpoint accepted")
	}
	meta.PushedAuthorizationRequestEndpoint = ""
	meta.RequirePushedAuthorizationRequests = true
	if err := meta.validate(); err == nil {
		t.Fatal("PAR required without an endpoint")
	}
}

func TestDPoPFlow(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.dpopAlgs = []string{"ES256"}
	p.dpopNonce = "as-nonce"
	prover := newProver(t)
	// A fixed auth style: auto-detection would resend a failed token
	// request on its own and hide whether the nonce retry works.
	c := newClient(t, p, withDPoP(prover), func(c *Config) { c.AuthStyle = oauth2.AuthStyleInHeader })

	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(req.URL)
	if u.Query().Get("dpop_jkt") != prover.Thumbprint() {
		t.Fatalf("dpop_jkt = %q", u.Query().Get("dpop_jkt"))
	}
	state, code := p.authorize(t, req.URL)
	// The first token request lacks the nonce; the retry carries it.
	res, err := c.Exchange(ctx, req, state, code)
	if err != nil {
		t.Fatalf("Exchange = %v", err)
	}
	if res.Token.TokenType != "DPoP" {
		t.Fatalf("token_type = %q", res.Token.TokenType)
	}

	resp, err := c.HTTPClient(ctx, res.Token).Get(p.URL + "/api")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "dpop:"+res.Token.AccessToken {
		t.Fatalf("resource response %d %q", resp.StatusCode, body)
	}
}

func TestDPoPCodeBinding(t *testing.T) {
	ctx := context.Background()
	for name, push := range map[string]bool{"dpop_jkt": false, "PAR with proof": true} {
		t.Run(name, func(t *testing.T) {
			p := newFakeProvider(t)
			p.par = true
			c := newClient(t, p, withDPoP(newProver(t)))
			req, err := c.AuthCodeURL()
			if push {
				req, err = c.PushAuthCodeURL(ctx)
			}
			if err != nil {
				t.Fatal(err)
			}
			if push && p.lastPush.Header.Get(dpop.HeaderName) == "" {
				t.Fatal("PAR request without a DPoP proof")
			}
			state, code := p.authorize(t, req.URL)
			// An attacker who steals the code cannot redeem it with
			// another key.
			thief := newClient(t, p, withDPoP(newProver(t)))
			if _, err := thief.Exchange(ctx, req, state, code); !errors.Is(err, ErrExchangeRejected) {
				t.Fatalf("code redeemed with another key: err = %v", err)
			}
		})
	}
}

func TestDPoPDowngradeRejected(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.bearerOnly = true
	c := newClient(t, p, withDPoP(newProver(t)))
	req, _ := c.AuthCodeURL()
	u, _ := url.Parse(req.URL)
	q := u.Query()
	q.Del("dpop_jkt") // a provider without DPoP support ignores it
	u.RawQuery = q.Encode()
	state, code := p.authorize(t, u.String())
	_, err := c.Exchange(ctx, req, state, code)
	if err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("Bearer token accepted with DPoP configured: err = %v", err)
	}
}

func TestDPoPAlgorithmMustBeSupported(t *testing.T) {
	p := newFakeProvider(t)
	p.dpopAlgs = []string{"RS256"}
	meta, err := Discover(context.Background(), p.URL, p.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(meta, Config{ClientID: clientID, RedirectURL: redirectURL, DPoP: newProver(t)}); err == nil {
		t.Fatal("unsupported DPoP algorithm accepted")
	}
}

func TestHTTPClientBearer(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	c := newClient(t, p)
	req, _ := c.AuthCodeURL()
	state, code := p.authorize(t, req.URL)
	res, err := c.Exchange(ctx, req, state, code)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.HTTPClient(ctx, res.Token).Get(p.URL + "/api")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "bearer:"+res.Token.AccessToken {
		t.Fatalf("resource response %d %q", resp.StatusCode, body)
	}
}

// FAPI 2.0 combines PAR, DPoP and private_key_jwt. When the provider asks
// for a DPoP nonce, the retry must carry a fresh client assertion: the
// fake provider, like a real one, accepts each assertion only once.
func TestPARWithDPoPAndPrivateKeyJWT(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.par = true
	p.dpopNonce = "nonce-1"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner(jwt.ES256, key)
	var err error
	p.assertionVerifier, err = jwt.NewVerifier(jwt.NewStaticKeySet(signer.VerificationKey()),
		jwt.WithAlgorithms(jwt.ES256), jwt.WithIssuer(clientID), jwt.WithAudience(p.URL),
		jwt.WithExpectedType("client-authentication+jwt"), jwt.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(t, p, withDPoP(newProver(t)), func(c *Config) {
		c.ClientSecret = ""
		c.PrivateKeyJWT = &PrivateKeyJWTConfig{Algorithm: jwt.ES256, PrivateKey: key}
	})

	req, err := c.PushAuthCodeURL(ctx)
	if err != nil {
		t.Fatalf("PushAuthCodeURL = %v", err)
	}
	// A new nonce forces a retry at the token endpoint as well.
	p.mu.Lock()
	p.dpopNonce = "nonce-2"
	p.mu.Unlock()
	state, code := p.authorize(t, req.URL)
	res, err := c.Exchange(ctx, req, state, code)
	if err != nil {
		t.Fatalf("Exchange = %v", err)
	}
	if res.Token.TokenType != "DPoP" {
		t.Fatalf("token_type = %q", res.Token.TokenType)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.assertions) != 4 {
		t.Fatalf("%d client assertions accepted, want 4 (two attempts at each endpoint)", len(p.assertions))
	}
}

func TestUserInfoWithDPoP(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	c := newClient(t, p, withDPoP(newProver(t)))
	res := login(t, p, c)
	if res.Token.TokenType != "DPoP" {
		t.Fatalf("token_type = %q", res.Token.TokenType)
	}
	info, err := c.UserInfo(ctx, res.Token, res.Principal.Subject)
	if err != nil {
		t.Fatalf("UserInfo = %v", err)
	}
	if info.Claims["email"] != "user42@example.com" {
		t.Fatalf("claims = %v", info.Claims)
	}

	// Without a Prover, a DPoP token cannot be used.
	plain := newClient(t, p)
	if _, err := plain.UserInfo(ctx, res.Token, res.Principal.Subject); err == nil {
		t.Fatal("DPoP token sent without a proof")
	}
}
