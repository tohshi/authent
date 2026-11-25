package oidc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent"
)

// userinfoHandler serves the UserInfo endpoint for access tokens issued by
// the token endpoint.
func (p *fakeProvider) userinfoHandler(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	valid := ok && p.accessTokens[tok]
	p.mu.Unlock()
	if !valid {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if p.userinfo != nil {
		p.userinfo(w, r)
		return
	}
	writeUserInfo(w, `{"sub":"user-42","email":"user42@example.com","email_verified":true}`)
}

func writeUserInfo(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(body))
}

// login runs the authorization code flow and returns its result.
func login(t *testing.T, p *fakeProvider, c *Client) *Result {
	t.Helper()
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatal(err)
	}
	state, code := p.authorize(t, req.URL)
	res, err := c.Exchange(context.Background(), req, state, code)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestUserInfo(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p)
	res := login(t, p, c)
	info, err := c.UserInfo(context.Background(), res.Token, res.Principal.Subject)
	if err != nil {
		t.Fatalf("UserInfo = %v", err)
	}
	if info.Subject != "user-42" || info.Claims["sub"] != "user-42" ||
		info.Claims["email"] != "user42@example.com" || info.Claims["email_verified"] != true {
		t.Fatalf("info = %+v", info)
	}
}

func TestUserInfoRejections(t *testing.T) {
	type tc struct {
		name     string
		userinfo func(w http.ResponseWriter, r *http.Request)
		token    func(tok *oauth2.Token)
		want     error // nil: must not wrap authent.ErrUnauthenticated
	}
	body := func(s string) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) { writeUserInfo(w, s) }
	}
	withType := func(ct, s string) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", ct)
			_, _ = w.Write([]byte(s))
		}
	}
	status := func(code int) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
	}
	for _, tc := range []tc{
		{name: "sub mismatch", userinfo: body(`{"sub":"user-43","email":"attacker@example.com"}`), want: ErrInvalidUserInfo},
		{name: "missing sub", userinfo: body(`{"email":"user42@example.com"}`), want: ErrInvalidUserInfo},
		{name: "non-string sub", userinfo: body(`{"sub":42}`), want: ErrInvalidUserInfo},
		{name: "sub differs in case", userinfo: body(`{"sub":"USER-42"}`), want: ErrInvalidUserInfo},
		{name: "duplicate sub", userinfo: body(`{"sub":"user-43","sub":"user-42"}`), want: ErrInvalidUserInfo},
		{name: "null", userinfo: body(`null`), want: ErrInvalidUserInfo},
		{name: "array", userinfo: body(`[{"sub":"user-42"}]`), want: ErrInvalidUserInfo},
		{name: "malformed", userinfo: body(`{"sub":"user-42"`), want: ErrInvalidUserInfo},
		{name: "signed response", userinfo: withType("application/jwt", "eyJhbGciOiJub25lIn0.e30."), want: ErrInvalidUserInfo},
		{name: "html", userinfo: withType("text/html", `{"sub":"user-42"}`), want: ErrInvalidUserInfo},
		{name: "no content type", userinfo: withType("", `{"sub":"user-42"}`), want: ErrInvalidUserInfo},
		{name: "invalid access token", token: func(tok *oauth2.Token) { tok.AccessToken = "forged" }, want: ErrUserInfoRejected},
		{name: "insufficient scope", userinfo: status(http.StatusForbidden), want: ErrUserInfoRejected},
		{name: "server error", userinfo: status(http.StatusInternalServerError)},
		{name: "too large", userinfo: body(`{"sub":"user-42","x":"` + strings.Repeat("a", maxUserInfoSize) + `"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t)
			c := newClient(t, p)
			res := login(t, p, c)
			p.userinfo = tc.userinfo
			if tc.token != nil {
				tc.token(res.Token)
			}
			info, err := c.UserInfo(context.Background(), res.Token, res.Principal.Subject)
			if err == nil || info != nil {
				t.Fatalf("UserInfo = %+v, %v; want error", info, err)
			}
			if tc.want == nil {
				if errors.Is(err, authent.ErrUnauthenticated) {
					t.Fatalf("err = %v wraps ErrUnauthenticated", err)
				}
				return
			}
			if !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUserInfoDoesNotFollowRedirects(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p)
	res := login(t, p, c)
	var leaked atomic.Bool
	p.Config.Handler.(*http.ServeMux).HandleFunc("GET /elsewhere", func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(true)
		writeUserInfo(w, `{"sub":"user-42"}`)
	})
	p.userinfo = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, p.URL+"/elsewhere", http.StatusFound)
	}
	if _, err := c.UserInfo(context.Background(), res.Token, res.Principal.Subject); err == nil {
		t.Fatal("redirect accepted")
	}
	if leaked.Load() {
		t.Fatal("redirect followed")
	}
}

func TestUserInfoRequiresArguments(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p)
	var requests atomic.Int32
	p.userinfo = func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		writeUserInfo(w, `{"sub":"user-42"}`)
	}
	ctx := context.Background()
	bearer := &oauth2.Token{AccessToken: "a", TokenType: "Bearer"}
	for name, call := range map[string]func() error{
		"nil token":   func() error { _, err := c.UserInfo(ctx, nil, "user-42"); return err },
		"empty token": func() error { _, err := c.UserInfo(ctx, &oauth2.Token{}, "user-42"); return err },
		"DPoP token": func() error {
			_, err := c.UserInfo(ctx, &oauth2.Token{AccessToken: "a", TokenType: "DPoP"}, "user-42")
			return err
		},
		"empty sub": func() error { _, err := c.UserInfo(ctx, bearer, ""); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d requests sent", n)
	}
}

func TestUserInfoWithoutEndpoint(t *testing.T) {
	p := newFakeProvider(t)
	p.userinfoEndpoint = "-"
	c := newClient(t, p)
	_, err := c.UserInfo(context.Background(), &oauth2.Token{AccessToken: "a"}, "user-42")
	if !errors.Is(err, ErrNoUserInfoEndpoint) || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrNoUserInfoEndpoint", err)
	}
}

func TestDiscoverRejectsInsecureUserInfoEndpoint(t *testing.T) {
	p := newFakeProvider(t)
	p.userinfoEndpoint = "http://insecure.example/userinfo"
	if _, err := Discover(context.Background(), p.URL, p.Client()); err == nil {
		t.Fatal("http userinfo_endpoint accepted")
	}
}
