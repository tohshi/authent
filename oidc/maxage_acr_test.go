package oidc

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

var (
	maxAge5m   = oauth2.SetAuthURLParam("max_age", "300")
	acrMFAOrHW = oauth2.SetAuthURLParam("acr_values", "urn:example:mfa urn:example:hwk")
)

func TestMaxAgeAndACR(t *testing.T) {
	ctx := context.Background()
	authTime := now.Add(-4 * time.Minute)
	for name, push := range map[string]bool{"query": false, "pushed": true} {
		t.Run(name, func(t *testing.T) {
			p := newFakeProvider(t)
			p.par = true
			p.mutate = func(c *jwt.Claims) {
				c.Extra["auth_time"] = authTime.Unix()
				c.Extra["acr"] = "urn:example:hwk"
			}
			c := newClient(t, p)
			req, err := c.AuthCodeURL(maxAge5m, acrMFAOrHW)
			if push {
				req, err = c.PushAuthCodeURL(ctx, maxAge5m, acrMFAOrHW)
			}
			if err != nil {
				t.Fatal(err)
			}
			if req.MaxAge == nil || *req.MaxAge != 5*time.Minute || len(req.ACRValues) != 2 {
				t.Fatalf("MaxAge = %v, ACRValues = %q", req.MaxAge, req.ACRValues)
			}
			u, _ := url.Parse(req.URL)
			sent := u.Query()
			if push {
				sent = p.lastPush.PostForm
			}
			if sent.Get("max_age") != "300" || sent.Get("acr_values") != "urn:example:mfa urn:example:hwk" {
				t.Fatalf("authorization request = %v", sent)
			}
			state, code := p.authorize(t, req.URL)
			res, err := c.Exchange(ctx, req, state, code)
			if err != nil {
				t.Fatalf("Exchange = %v", err)
			}
			if !res.Principal.AuthTime.Equal(authTime) {
				t.Fatalf("AuthTime = %v", res.Principal.AuthTime)
			}
		})
	}
}

func TestMaxAgeZero(t *testing.T) {
	for name, tc := range map[string]struct {
		authTime time.Time
		want     error
	}{
		"just authenticated":           {now, nil},
		"older than the leeway":        {now.Add(-61 * time.Second), jwt.ErrAuthenticationTooOld},
		"within the one minute leeway": {now.Add(-time.Minute), nil},
	} {
		t.Run(name, func(t *testing.T) {
			p := newFakeProvider(t)
			p.mutate = func(c *jwt.Claims) { c.Extra["auth_time"] = tc.authTime.Unix() }
			c := newClient(t, p)
			req, err := c.AuthCodeURL(oauth2.SetAuthURLParam("max_age", "0"))
			if err != nil {
				t.Fatal(err)
			}
			if req.MaxAge == nil || *req.MaxAge != 0 {
				t.Fatalf("MaxAge = %v", req.MaxAge)
			}
			state, code := p.authorize(t, req.URL)
			if _, err := c.Exchange(context.Background(), req, state, code); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMaxAgeAndACRRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opt    oauth2.AuthCodeOption
		claims map[string]any
		want   error
	}{
		{"auth_time missing", maxAge5m, nil, jwt.ErrMissingClaim},
		{"auth_time too old", maxAge5m, map[string]any{"auth_time": now.Add(-6*time.Minute - time.Second).Unix()}, jwt.ErrAuthenticationTooOld},
		{"auth_time in the future", maxAge5m, map[string]any{"auth_time": now.Add(2 * time.Minute).Unix()}, jwt.ErrIssuedInFuture},
		{"auth_time not a number", maxAge5m, map[string]any{"auth_time": "yesterday"}, jwt.ErrMalformed},
		{"acr missing", acrMFAOrHW, nil, ErrInvalidIDToken},
		{"acr not requested", acrMFAOrHW, map[string]any{"acr": "urn:example:pwd"}, ErrInvalidIDToken},
		{"acr not a string", acrMFAOrHW, map[string]any{"acr": 2}, ErrInvalidIDToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t)
			p.mutate = func(c *jwt.Claims) {
				for k, v := range tc.claims {
					c.Extra[k] = v
				}
			}
			c := newClient(t, p)
			req, err := c.AuthCodeURL(tc.opt)
			if err != nil {
				t.Fatal(err)
			}
			state, code := p.authorize(t, req.URL)
			_, err = c.Exchange(context.Background(), req, state, code)
			if !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestExchangeRejectsTruncatedAuthRequest(t *testing.T) {
	zero := time.Duration(0)
	for name, tc := range map[string]struct {
		opts   []oauth2.AuthCodeOption
		change func(*AuthRequest)
	}{
		"MaxAge dropped":       {[]oauth2.AuthCodeOption{maxAge5m}, func(r *AuthRequest) { r.MaxAge = nil }},
		"MaxAge changed":       {[]oauth2.AuthCodeOption{maxAge5m}, func(r *AuthRequest) { r.MaxAge = &zero }},
		"ACRValues dropped":    {[]oauth2.AuthCodeOption{acrMFAOrHW}, func(r *AuthRequest) { r.ACRValues = nil }},
		"ACRValues narrowed":   {[]oauth2.AuthCodeOption{acrMFAOrHW}, func(r *AuthRequest) { r.ACRValues = r.ACRValues[:1] }},
		"MaxAge added":         {nil, func(r *AuthRequest) { r.MaxAge = &zero }},
		"only State and Nonce": {[]oauth2.AuthCodeOption{maxAge5m, acrMFAOrHW}, func(r *AuthRequest) { *r = AuthRequest{State: r.State, Nonce: r.Nonce, CodeVerifier: r.CodeVerifier} }},
	} {
		t.Run(name, func(t *testing.T) {
			p := newFakeProvider(t)
			p.mutate = func(c *jwt.Claims) {
				c.Extra["auth_time"] = now.Unix()
				c.Extra["acr"] = "urn:example:mfa"
			}
			c := newClient(t, p)
			req, err := c.AuthCodeURL(tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			state, code := p.authorize(t, req.URL)
			tc.change(&req)
			if res, err := c.Exchange(context.Background(), req, state, code); err == nil {
				t.Fatalf("Exchange = %+v with a changed AuthRequest", res.Principal)
			}
		})
	}
}

func TestAuthCodeURLRejectsInvalidMaxAgeAndACR(t *testing.T) {
	c := newClient(t, newFakeProvider(t))
	for _, opt := range []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("max_age", "-1"),
		oauth2.SetAuthURLParam("max_age", "+5"),
		oauth2.SetAuthURLParam("max_age", "1.5"),
		oauth2.SetAuthURLParam("max_age", "5m"),
		oauth2.SetAuthURLParam("max_age", ""),
		oauth2.SetAuthURLParam("max_age", "99999999999999999999"),
		oauth2.SetAuthURLParam("acr_values", " "),
	} {
		if req, err := c.AuthCodeURL(opt); err == nil {
			t.Errorf("AuthCodeURL accepted %s", req.URL)
		}
	}
}
