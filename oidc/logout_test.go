package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

func TestEndSessionURL(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p)
	got, err := c.EndSessionURL(EndSession{
		IDTokenHint:           "id.token.hint",
		PostLogoutRedirectURI: "https://app.example/logged-out",
		State:                 "s1",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	want := url.Values{
		"tenant":                   {"t1"},
		"client_id":                {clientID},
		"id_token_hint":            {"id.token.hint"},
		"post_logout_redirect_uri": {"https://app.example/logged-out"},
		"state":                    {"s1"},
	}
	if u.Scheme+"://"+u.Host+u.Path != p.URL+"/end_session" || u.Query().Encode() != want.Encode() {
		t.Fatalf("URL = %s", got)
	}

	got, err = c.EndSessionURL(EndSession{IDTokenHint: "id.token.hint"})
	if err != nil {
		t.Fatal(err)
	}
	if q, _ := url.ParseQuery(got[len(p.URL+"/end_session?"):]); q.Has("state") || q.Has("post_logout_redirect_uri") {
		t.Fatalf("URL = %s", got)
	}

	if _, err := c.EndSessionURL(EndSession{State: "s1"}); err == nil {
		t.Fatal("state accepted without a post-logout redirect URI")
	}
}

func TestEndSessionURLWithoutEndpoint(t *testing.T) {
	p := newFakeProvider(t)
	meta := &Provider{Issuer: p.URL, AuthorizationEndpoint: p.URL + "/authorize",
		TokenEndpoint: p.URL + "/token", JWKSURI: p.URL + "/jwks"}
	c, err := NewClient(meta, Config{ClientID: clientID, RedirectURL: redirectURL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.EndSessionURL(EndSession{}); !errors.Is(err, ErrNoEndSessionEndpoint) {
		t.Fatalf("err = %v", err)
	}
	meta.EndSessionEndpoint = "http://op.example/logout"
	if err := meta.validate(); err == nil {
		t.Fatal("http end_session_endpoint accepted")
	}
}

func TestFrontChannelLogout(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p)
	got, err := c.FrontChannelLogout(url.Values{"iss": {p.URL}, "sid": {"session-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if *got != (Logout{Issuer: p.URL, SessionID: "session-1"}) {
		t.Fatalf("logout = %+v", got)
	}
	for name, q := range map[string]url.Values{
		"no parameters":  {},
		"missing sid":    {"iss": {p.URL}},
		"missing iss":    {"sid": {"session-1"}},
		"empty sid":      {"iss": {p.URL}, "sid": {""}},
		"other issuer":   {"iss": {"https://evil.example"}, "sid": {"session-1"}},
		"issuer prefix":  {"iss": {p.URL + "/"}, "sid": {"session-1"}},
		"duplicate iss":  {"iss": {"https://evil.example", p.URL}, "sid": {"session-1"}},
		"duplicate sid":  {"iss": {p.URL}, "sid": {"session-1", "session-2"}},
		"issuer in case": {"ISS": {p.URL}, "sid": {"session-1"}},
	} {
		if got, err := c.FrontChannelLogout(q); !errors.Is(err, ErrInvalidLogout) || !errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("%s: FrontChannelLogout = %+v, %v", name, got, err)
		}
	}
}

func validLogoutClaims(p *fakeProvider) jwt.Claims {
	jti, _ := randomString()
	return jwt.Claims{
		Issuer:    p.URL,
		Subject:   "user-42",
		Audience:  jwt.Audience{clientID},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
		ID:        jti,
		Extra: map[string]any{
			"sid":    "session-1",
			"events": map[string]any{logoutEvent: map[string]any{}},
		},
	}
}

func signLogoutToken(t testing.TB, key *ecdsa.PrivateKey, typ string, c jwt.Claims) string {
	t.Helper()
	opts := []jwt.SignerOption{jwt.WithKeyID("k1")}
	if typ != "" {
		opts = append(opts, jwt.WithType(typ))
	}
	signer, err := jwt.NewSigner(jwt.ES256, key, opts...)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := signer.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestBackChannelLogout(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	c := newClient(t, p)
	for name, tc := range map[string]struct {
		typ    string
		mutate func(*jwt.Claims)
		want   Logout
	}{
		"sub and sid": {logoutTokenType, nil, Logout{Issuer: p.URL, Subject: "user-42", SessionID: "session-1"}},
		"sid only":    {logoutTokenType, func(c *jwt.Claims) { c.Subject = "" }, Logout{Issuer: p.URL, SessionID: "session-1"}},
		"sub only":    {logoutTokenType, func(c *jwt.Claims) { delete(c.Extra, "sid") }, Logout{Issuer: p.URL, Subject: "user-42"}},
		"media type":  {"application/logout+jwt", nil, Logout{Issuer: p.URL, Subject: "user-42", SessionID: "session-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			claims := validLogoutClaims(p)
			if tc.mutate != nil {
				tc.mutate(&claims)
			}
			got, err := c.BackChannelLogout(ctx, signLogoutToken(t, p.signerKey, tc.typ, claims))
			if err != nil {
				t.Fatalf("BackChannelLogout = %v", err)
			}
			if *got != tc.want {
				t.Fatalf("logout = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestBackChannelLogoutRejections(t *testing.T) {
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	setExtra := func(k string, v any) func(*jwt.Claims) {
		return func(c *jwt.Claims) { c.Extra[k] = v }
	}
	for _, tc := range []struct {
		name   string
		typ    string
		key    *ecdsa.PrivateKey
		mutate func(*jwt.Claims)
		want   error
	}{
		{name: "ID token type", typ: "JWT", want: jwt.ErrUnexpectedType},
		{name: "untyped", typ: "-", want: jwt.ErrUnexpectedType},
		{name: "foreign key", key: otherKey, want: jwt.ErrInvalidSignature},
		{name: "other issuer", mutate: func(c *jwt.Claims) { c.Issuer = "https://evil.example" }, want: jwt.ErrInvalidIssuer},
		{name: "other audience", mutate: func(c *jwt.Claims) { c.Audience = jwt.Audience{"other-client"} }, want: jwt.ErrInvalidAudience},
		{name: "expired", mutate: func(c *jwt.Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-2 * time.Minute)) }, want: jwt.ErrExpired},
		{name: "no exp", mutate: func(c *jwt.Claims) { c.ExpiresAt = jwt.NumericDate{} }, want: jwt.ErrMissingClaim},
		{name: "no iat", mutate: func(c *jwt.Claims) { c.IssuedAt = jwt.NumericDate{} }, want: jwt.ErrMissingClaim},
		{name: "issued too long ago", mutate: func(c *jwt.Claims) { c.IssuedAt = jwt.NewNumericDate(now.Add(-3*time.Minute - time.Second)) }, want: jwt.ErrTokenTooOld},
		{name: "issued in the future", mutate: func(c *jwt.Claims) { c.IssuedAt = jwt.NewNumericDate(now.Add(2 * time.Minute)) }, want: jwt.ErrIssuedInFuture},
		{name: "no jti", mutate: func(c *jwt.Claims) { c.ID = "" }, want: jwt.ErrMissingClaim},
		{name: "no events", mutate: func(c *jwt.Claims) { delete(c.Extra, "events") }, want: ErrInvalidLogout},
		{name: "events not an object", mutate: setExtra("events", []string{logoutEvent}), want: ErrInvalidLogout},
		{name: "other event", mutate: setExtra("events", map[string]any{"http://schemas.openid.net/event/other": map[string]any{}}), want: ErrInvalidLogout},
		{name: "event not an object", mutate: setExtra("events", map[string]any{logoutEvent: true}), want: ErrInvalidLogout},
		{name: "nonce", mutate: setExtra("nonce", "n"), want: ErrInvalidLogout},
		{name: "neither sub nor sid", mutate: func(c *jwt.Claims) { c.Subject = ""; delete(c.Extra, "sid") }, want: ErrInvalidLogout},
		{name: "empty sid only", mutate: func(c *jwt.Claims) { c.Subject = ""; c.Extra["sid"] = "" }, want: ErrInvalidLogout},
		{name: "sid not a string", mutate: setExtra("sid", 7), want: ErrInvalidLogout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t)
			c := newClient(t, p)
			claims := validLogoutClaims(p)
			if tc.mutate != nil {
				tc.mutate(&claims)
			}
			key, typ := p.signerKey, logoutTokenType
			if tc.key != nil {
				key = tc.key
			}
			switch tc.typ {
			case "-":
				typ = ""
			case "":
			default:
				typ = tc.typ
			}
			got, err := c.BackChannelLogout(context.Background(), signLogoutToken(t, key, typ, claims))
			if got != nil || !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("BackChannelLogout = %+v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestBackChannelLogoutRejectsIDToken(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p)
	res := login(t, p, c)
	if _, err := c.BackChannelLogout(context.Background(), res.RawIDToken); !errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("ID token accepted as a logout token: err = %v", err)
	}
}

func TestBackChannelLogoutReplay(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	cache := jwt.NewMemoryReplayCache()
	first := newClient(t, p, func(c *Config) { c.ReplayCache = cache })
	second := newClient(t, p, func(c *Config) { c.ReplayCache = cache })
	tok := signLogoutToken(t, p.signerKey, logoutTokenType, validLogoutClaims(p))
	if _, err := first.BackChannelLogout(ctx, tok); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*Client{"same client": first, "client sharing the cache": second} {
		if _, err := c.BackChannelLogout(ctx, tok); !errors.Is(err, jwt.ErrReplayed) {
			t.Errorf("%s: replay err = %v", name, err)
		}
	}
	if _, err := first.BackChannelLogout(ctx, signLogoutToken(t, p.signerKey, logoutTokenType, validLogoutClaims(p))); err != nil {
		t.Fatalf("fresh jti rejected: %v", err)
	}
}

func TestBackChannelLogoutRejectionKeepsJTI(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	c := newClient(t, p)
	for name, mutate := range map[string]func(*jwt.Claims){
		"nonce":               func(c *jwt.Claims) { c.Extra["nonce"] = "n" },
		"no event":            func(c *jwt.Claims) { delete(c.Extra, "events") },
		"neither sub nor sid": func(c *jwt.Claims) { c.Subject = ""; delete(c.Extra, "sid") },
	} {
		valid := validLogoutClaims(p)
		invalid := validLogoutClaims(p)
		invalid.ID = valid.ID
		mutate(&invalid)
		if _, err := c.BackChannelLogout(ctx, signLogoutToken(t, p.signerKey, logoutTokenType, invalid)); !errors.Is(err, ErrInvalidLogout) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if _, err := c.BackChannelLogout(ctx, signLogoutToken(t, p.signerKey, logoutTokenType, valid)); err != nil {
			t.Errorf("%s: a rejected token used up the jti: %v", name, err)
		}
	}
}

type failingCache struct{}

func (failingCache) Add(context.Context, string, time.Duration) (bool, error) {
	return false, errors.New("store unavailable")
}

func TestBackChannelLogoutReplayCacheError(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p, func(c *Config) { c.ReplayCache = failingCache{} })
	_, err := c.BackChannelLogout(context.Background(), signLogoutToken(t, p.signerKey, logoutTokenType, validLogoutClaims(p)))
	if err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("err = %v, want an error not wrapping ErrUnauthenticated", err)
	}
}

func TestLogoutMatches(t *testing.T) {
	const iss = "https://op.example"
	idToken := func(sub, sid string) *jwt.Claims {
		c := &jwt.Claims{Issuer: iss, Subject: sub, Extra: map[string]any{}}
		if sid != "" {
			c.Extra["sid"] = sid
		}
		return c
	}
	for _, tc := range []struct {
		name   string
		logout Logout
		token  *jwt.Claims
		want   bool
	}{
		{"session", Logout{Issuer: iss, SessionID: "s1"}, idToken("u1", "s1"), true},
		{"other session", Logout{Issuer: iss, SessionID: "s1"}, idToken("u1", "s2"), false},
		{"session of a token without sid", Logout{Issuer: iss, SessionID: "s1"}, idToken("u1", ""), false},
		{"all sessions of the subject", Logout{Issuer: iss, Subject: "u1"}, idToken("u1", "s2"), true},
		{"other subject", Logout{Issuer: iss, Subject: "u1"}, idToken("u2", "s1"), false},
		{"subject and session", Logout{Issuer: iss, Subject: "u1", SessionID: "s1"}, idToken("u1", "s1"), true},
		{"session of another subject", Logout{Issuer: iss, Subject: "u1", SessionID: "s1"}, idToken("u2", "s1"), false},
		{"other issuer", Logout{Issuer: "https://other.example", SessionID: "s1"}, idToken("u1", "s1"), false},
		{"no ID token", Logout{Issuer: iss, SessionID: "s1"}, nil, false},
	} {
		if got := tc.logout.Matches(tc.token); got != tc.want {
			t.Errorf("%s: Matches = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func FuzzBackChannelLogout(f *testing.F) {
	p := newFakeProvider(f)
	c := newClient(f, p, func(c *Config) { c.ReplayCache = noReplayCheck{} })
	f.Add(signLogoutToken(f, p.signerKey, logoutTokenType, validLogoutClaims(p)))
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Fuzz(func(t *testing.T, token string) {
		got, err := c.BackChannelLogout(context.Background(), token)
		if err != nil {
			if !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v, want a rejection", err)
			}
			return
		}
		if got.Issuer != p.URL || got.Subject == "" && got.SessionID == "" {
			t.Fatalf("accepted %+v", got)
		}
	})
}

type noReplayCheck struct{}

func (noReplayCheck) Add(context.Context, string, time.Duration) (bool, error) { return true, nil }
