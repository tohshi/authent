package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

// withPrivateKeyJWT makes p require private_key_jwt and returns the
// matching client configuration.
func withPrivateKeyJWT(t *testing.T, p *fakeProvider) func(*Config) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, err := jwt.NewSigner(jwt.ES256, key)
	if err != nil {
		t.Fatal(err)
	}
	p.assertionVerifier, err = jwt.NewVerifier(jwt.NewStaticKeySet(signer.VerificationKey()),
		jwt.WithAlgorithms(jwt.ES256), jwt.WithIssuer(clientID), jwt.WithAudience(p.URL),
		jwt.WithExpectedType("client-authentication+jwt"), jwt.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return func(c *Config) {
		c.ClientSecret = ""
		c.PrivateKeyJWT = &PrivateKeyJWTConfig{Algorithm: jwt.ES256, PrivateKey: key}
	}
}

func (p *fakeProvider) assertionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.assertions)
}

func TestRefresh(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		dpop bool
		mods func(t *testing.T, p *fakeProvider) []func(*Config)
	}{
		{name: "client_secret_basic", mods: func(*testing.T, *fakeProvider) []func(*Config) {
			return []func(*Config){func(c *Config) { c.AuthStyle = oauth2.AuthStyleInHeader }}
		}},
		{name: "client_secret_post", mods: func(*testing.T, *fakeProvider) []func(*Config) {
			return []func(*Config){func(c *Config) { c.AuthStyle = oauth2.AuthStyleInParams }}
		}},
		{name: "private_key_jwt", mods: func(t *testing.T, p *fakeProvider) []func(*Config) {
			return []func(*Config){withPrivateKeyJWT(t, p)}
		}},
		{name: "DPoP and private_key_jwt with a new nonce", dpop: true, mods: func(t *testing.T, p *fakeProvider) []func(*Config) {
			p.dpopNonce = "nonce-1"
			return []func(*Config){withPrivateKeyJWT(t, p), withDPoP(newProver(t))}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t)
			c := newClient(t, p, tc.mods(t, p)...)
			res := login(t, p, c)
			p.mu.Lock()
			p.dpopNonce = "nonce-2"
			p.mutateRefresh = func(c *jwt.Claims) { c.Extra["email"] = "new@example.com" }
			p.mu.Unlock()
			assertions := p.assertionCount()

			next, err := c.Refresh(ctx, res)
			if err != nil {
				t.Fatalf("Refresh = %v", err)
			}
			if next.Token.AccessToken == res.Token.AccessToken || next.Token.RefreshToken != res.Token.RefreshToken {
				t.Fatalf("tokens = %+v, before %+v", next.Token, res.Token)
			}
			if next.Principal.Subject != "user-42" || next.Principal.Claims["email"] != "new@example.com" ||
				next.IDToken.Extra["email"] != "new@example.com" || next.RawIDToken == res.RawIDToken {
				t.Fatalf("result = %+v", next)
			}
			if tc.dpop && next.Token.TokenType != "DPoP" {
				t.Fatalf("token_type = %q", next.Token.TokenType)
			}
			if p.assertionVerifier != nil {
				want := 1
				if tc.dpop {
					want = 2
				}
				if got := p.assertionCount() - assertions; got != want {
					t.Fatalf("%d client assertions accepted at refresh, want %d", got, want)
				}
			}
		})
	}
}

func TestRefreshRotation(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.rotateRefresh = true
	c := newClient(t, p)
	res := login(t, p, c)
	next, err := c.Refresh(ctx, res)
	if err != nil {
		t.Fatal(err)
	}
	if next.Token.RefreshToken == "" || next.Token.RefreshToken == res.Token.RefreshToken {
		t.Fatalf("refresh token not rotated: %q", next.Token.RefreshToken)
	}
	if _, err := c.Refresh(ctx, res); !errors.Is(err, ErrRefreshRejected) || !errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("rotated-out refresh token: err = %v", err)
	}
	if _, err := c.Refresh(ctx, next); err != nil {
		t.Fatalf("rotated refresh token: %v", err)
	}
}

func TestRefreshWithoutIDToken(t *testing.T) {
	p := newFakeProvider(t)
	p.omitRefreshIDToken = true
	c := newClient(t, p)
	res := login(t, p, c)
	next, err := c.Refresh(context.Background(), res)
	if err != nil {
		t.Fatal(err)
	}
	if next.Token.AccessToken == res.Token.AccessToken || next.IDToken != res.IDToken ||
		next.RawIDToken != res.RawIDToken || next.Principal.Subject != "user-42" {
		t.Fatalf("result = %+v", next)
	}
}

func TestRefreshedIDTokenChecks(t *testing.T) {
	setExtra := func(k string, v any) func(*jwt.Claims) {
		return func(c *jwt.Claims) {
			if v == nil {
				delete(c.Extra, k)
				return
			}
			c.Extra[k] = v
		}
	}
	twoAudiences := func(c *jwt.Claims) {
		c.Audience = jwt.Audience{clientID, "api"}
		c.Extra["azp"] = clientID
	}
	authTime := now.Add(-time.Hour).Unix()
	for _, tc := range []struct {
		name      string
		original  func(*jwt.Claims)
		refresh   func(*jwt.Claims)
		want      error // nil: accepted
		copyNonce bool
	}{
		{name: "nonce of the original", copyNonce: true},
		{name: "same auth_time", original: setExtra("auth_time", authTime), refresh: setExtra("auth_time", authTime)},
		{name: "auth_time left out", original: setExtra("auth_time", authTime)},
		{name: "audiences reordered", original: twoAudiences, refresh: func(c *jwt.Claims) {
			c.Audience = jwt.Audience{"api", clientID}
			c.Extra["azp"] = clientID
		}},
		{name: "different sub", refresh: func(c *jwt.Claims) { c.Subject = "user-43" }, want: ErrInvalidIDToken},
		{name: "different issuer", refresh: func(c *jwt.Claims) { c.Issuer = "https://evil.example" }, want: jwt.ErrInvalidIssuer},
		{name: "client not in aud", refresh: func(c *jwt.Claims) { c.Audience = jwt.Audience{"api"} }, want: jwt.ErrInvalidAudience},
		{name: "audience added", refresh: twoAudiences, want: ErrInvalidIDToken},
		{name: "audience removed", original: twoAudiences, refresh: setExtra("azp", clientID), want: ErrInvalidIDToken},
		{name: "azp added", refresh: setExtra("azp", clientID), want: ErrInvalidIDToken},
		{name: "azp removed", original: setExtra("azp", clientID), want: ErrInvalidIDToken},
		{name: "azp not a string", original: setExtra("azp", clientID), refresh: setExtra("azp", 1), want: ErrInvalidIDToken},
		{name: "different nonce", refresh: setExtra("nonce", "other"), want: ErrInvalidIDToken},
		{name: "empty nonce", refresh: setExtra("nonce", ""), want: ErrInvalidIDToken},
		{name: "auth_time changed", original: setExtra("auth_time", authTime), refresh: setExtra("auth_time", now.Unix()), want: ErrInvalidIDToken},
		{name: "auth_time added", refresh: setExtra("auth_time", authTime), want: ErrInvalidIDToken},
		{name: "auth_time malformed", original: setExtra("auth_time", authTime), refresh: setExtra("auth_time", "x"), want: jwt.ErrMalformed},
		{name: "expired", refresh: func(c *jwt.Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-2 * time.Minute)) }, want: jwt.ErrExpired},
		{name: "at_hash mismatch", refresh: setExtra("at_hash", "AAAAAAAAAAAAAAAAAAAAAA"), want: ErrInvalidIDToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t)
			p.mutate = tc.original
			c := newClient(t, p)
			res := login(t, p, c)
			p.mutateRefresh = tc.refresh
			if tc.copyNonce {
				p.mutateRefresh = setExtra("nonce", res.IDToken.Extra["nonce"])
			}
			_, err := c.Refresh(context.Background(), res)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Refresh = %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRefreshFailures(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	c := newClient(t, p)
	res := login(t, p, c)

	forged := *res
	forged.Token = &oauth2.Token{RefreshToken: "forged"}
	if _, err := c.Refresh(ctx, &forged); !errors.Is(err, ErrRefreshRejected) || !errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("unknown refresh token: err = %v", err)
	}

	for _, tc := range []struct {
		status   int
		body     string
		rejected bool
	}{
		{http.StatusBadRequest, `{"error":"invalid_grant"}`, true},
		{http.StatusUnauthorized, `{"error":"invalid_client"}`, true},
		{http.StatusBadRequest, ``, false},
		{http.StatusBadRequest, `<html>bad gateway</html>`, false},
		{http.StatusUnauthorized, `{}`, false},
		{http.StatusForbidden, `{"error":"access_denied"}`, false},
		{http.StatusRequestTimeout, `{"error":"invalid_grant"}`, false},
		{http.StatusTooManyRequests, `{"error":"slow_down"}`, false},
		{http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`, false},
	} {
		p.mu.Lock()
		p.tokenFailure.status, p.tokenFailure.body = tc.status, tc.body
		p.mu.Unlock()
		_, err := c.Refresh(ctx, res)
		if err == nil || errors.Is(err, ErrRefreshRejected) != tc.rejected || errors.Is(err, authent.ErrUnauthenticated) != tc.rejected {
			t.Errorf("%d %s: err = %v, want rejected = %v", tc.status, tc.body, err, tc.rejected)
		}
	}

	noIDToken := *res
	noIDToken.IDToken = nil
	for name, prev := range map[string]*Result{
		"nil result":       nil,
		"no token":         {IDToken: res.IDToken},
		"no refresh token": {IDToken: res.IDToken, Token: &oauth2.Token{AccessToken: "a"}},
		"no ID token":      &noIDToken,
	} {
		if _, err := c.Refresh(ctx, prev); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRefreshDPoP(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	c := newClient(t, p, withDPoP(newProver(t)))
	res := login(t, p, c)

	thief := newClient(t, p, withDPoP(newProver(t)))
	if _, err := thief.Refresh(ctx, res); !errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("refresh token used with another key: err = %v", err)
	}

	plain := newClient(t, p)
	bearer := login(t, p, plain)
	p.bearerOnly = true
	if _, err := c.Refresh(ctx, bearer); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("Bearer token accepted with DPoP configured: err = %v", err)
	}
}

func TestHTTPClientRefreshesWithPrivateKeyJWT(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	c := newClient(t, p, withPrivateKeyJWT(t, p))
	res := login(t, p, c)
	expired := *res.Token
	expired.Expiry = time.Now().Add(-time.Hour)
	assertions := p.assertionCount()

	resp, err := c.HTTPClient(ctx, &expired).Get(p.URL + "/api")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) == "bearer:"+expired.AccessToken || len(body) <= len("bearer:") {
		t.Fatalf("resource response %d %q", resp.StatusCode, body)
	}
	if p.assertionCount() != assertions+1 {
		t.Fatal("refresh was not authenticated with a client assertion")
	}
}

func TestExchangeProviderOutage(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p)
	req, _ := c.AuthCodeURL()
	state, code := p.authorize(t, req.URL)
	p.tokenFailure.status, p.tokenFailure.body = http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`
	if _, err := c.Exchange(context.Background(), req, state, code); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("err = %v, want an error not wrapping ErrUnauthenticated", err)
	}
}
