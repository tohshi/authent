package httpauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/apikey"
	"github.com/tohshi/authent/httpauth"
	"github.com/tohshi/authent/jwt"
	"github.com/tohshi/authent/session"
)

type fixture struct {
	verifier *jwt.Verifier
	token    string
	sessions *session.Manager
	keys     *apikey.Manager
	keyStore *failingStore
}

type failingStore struct {
	*apikey.MemoryStore
	err error
}

func (s *failingStore) Lookup(ctx context.Context, id string) (apikey.Record, error) {
	if s.err != nil {
		return apikey.Record{}, s.err
	}
	return s.MemoryStore.Lookup(ctx, id)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner(jwt.ES256, key)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(jwt.Claims{Issuer: "iss", Subject: "jwt-user", Audience: jwt.Audience{"api"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	v, err := jwt.NewVerifier(jwt.NewStaticKeySet(signer.VerificationKey()),
		jwt.WithAlgorithms(jwt.ES256), jwt.WithIssuer("iss"), jwt.WithAudience("api"))
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewManager(session.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	store := &failingStore{MemoryStore: apikey.NewMemoryStore()}
	keys, err := apikey.NewManager("test", store)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{verifier: v, token: token, sessions: sessions, keys: keys, keyStore: store}
}

var whoami = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	p, ok := authent.FromContext(r.Context())
	if !ok {
		io.WriteString(w, "anonymous")
		return
	}
	io.WriteString(w, p.Subject+" "+string(p.Method))
})

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func withAuth(values ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, v := range values {
		r.Header.Add("Authorization", v)
	}
	return r
}

func TestBearer(t *testing.T) {
	f := newFixture(t)
	require := httpauth.Require(httpauth.Bearer(f.verifier))(whoami)
	optional := httpauth.Optional(httpauth.Bearer(f.verifier))(whoami)

	cases := []struct {
		name      string
		req       *http.Request
		h         http.Handler
		code      int
		body      string
		challenge string
	}{
		{"valid", withAuth("Bearer " + f.token), require, 200, "jwt-user jwt", ""},
		{"scheme is case-insensitive", withAuth("bearer " + f.token), require, 200, "jwt-user jwt", ""},
		{"missing", withAuth(), require, 401, "", "Bearer"},
		{"other scheme", withAuth("Basic dTpw"), require, 401, "", "Bearer"},
		{"invalid token", withAuth("Bearer " + f.token + "x"), require, 401, "", `Bearer error="invalid_token"`},
		{"no token", withAuth("Bearer "), require, 401, "", `Bearer error="invalid_token"`},
		{"not a b64token", withAuth("Bearer a b"), require, 401, "", `Bearer error="invalid_token"`},
		{"several headers", withAuth("Bearer "+f.token, "Bearer "+f.token), require, 401, "", `Bearer error="invalid_token"`},
		{"optional, missing", withAuth(), optional, 200, "anonymous", ""},
		{"optional, other scheme", withAuth("Basic dTpw"), optional, 200, "anonymous", ""},
		{"optional, valid", withAuth("Bearer " + f.token), optional, 200, "jwt-user jwt", ""},
		{"optional, invalid token", withAuth("Bearer " + f.token + "x"), optional, 401, "", `Bearer error="invalid_token"`},
	}
	for _, c := range cases {
		w := serve(c.h, c.req)
		if w.Code != c.code || (c.body != "" && w.Body.String() != c.body) {
			t.Errorf("%s: got %d %q, want %d %q", c.name, w.Code, w.Body.String(), c.code, c.body)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != c.challenge {
			t.Errorf("%s: WWW-Authenticate = %q, want %q", c.name, got, c.challenge)
		}
	}
}

func TestBearerToken(t *testing.T) {
	for in, want := range map[string]string{
		"Bearer abc":           "abc",
		"BEARER  a-b.c_d~e+/=": "a-b.c_d~e+/=",
		"Bearer abc==":         "abc==",
	} {
		if got, err := httpauth.BearerToken(in); err != nil || got != want {
			t.Errorf("BearerToken(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "Basic abc", "Bearerabc", "DPoP abc"} {
		if _, err := httpauth.BearerToken(in); !errors.Is(err, httpauth.ErrNoCredentials) {
			t.Errorf("BearerToken(%q): err = %v, want ErrNoCredentials", in, err)
		}
	}
	for _, in := range []string{"Bearer", "bearer", "Bearer ", "Bearer\t", "Bearer\tabc", "Bearer a b", "Bearer =", "Bearer a=b", "Bearer a\tb", "Bearer ä"} {
		_, err := httpauth.BearerToken(in)
		if !errors.Is(err, authent.ErrUnauthenticated) || errors.Is(err, httpauth.ErrNoCredentials) {
			t.Errorf("BearerToken(%q): err = %v, want a rejected token", in, err)
		}
	}
}

func TestAPIKeyAndAny(t *testing.T) {
	f := newFixture(t)
	key, rec, err := f.keys.Create(t.Context(), "svc", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h := httpauth.Require(httpauth.Any(httpauth.APIKey(f.keys), httpauth.Bearer(f.verifier)))(whoami)

	if w := serve(h, withAuth("Bearer "+key)); w.Code != 200 || w.Body.String() != "svc apikey" {
		t.Fatalf("API key: got %d %q", w.Code, w.Body.String())
	}
	if w := serve(h, withAuth("Bearer "+f.token)); w.Code != 200 || w.Body.String() != "jwt-user jwt" {
		t.Fatalf("JWT: got %d %q", w.Code, w.Body.String())
	}
	if w := serve(h, withAuth()); w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("missing: got %d, challenge %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}

	if err := f.keys.Revoke(t.Context(), rec.ID); err != nil {
		t.Fatal(err)
	}
	w := serve(h, withAuth("Bearer "+key))
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("revoked key: got %d, challenge %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}

	keysOnly := httpauth.Optional(httpauth.APIKey(f.keys))(whoami)
	if w := serve(keysOnly, withAuth("Bearer "+f.token)); w.Code != 200 || w.Body.String() != "anonymous" {
		t.Fatalf("JWT with API keys only: got %d %q", w.Code, w.Body.String())
	}
	if w := serve(keysOnly, withAuth("Bearer "+key[:len(key)-1])); w.Code != 401 {
		t.Fatalf("malformed API key with Optional: got %d", w.Code)
	}
}

func TestInfrastructureErrorsAreNotLeaked(t *testing.T) {
	f := newFixture(t)
	key, _, err := f.keys.Create(t.Context(), "svc", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.keyStore.err = errors.New("dial tcp 10.0.0.7: password=hunter2")
	for name, h := range map[string]http.Handler{
		"Require":  httpauth.Require(httpauth.APIKey(f.keys))(whoami),
		"Optional": httpauth.Optional(httpauth.APIKey(f.keys))(whoami),
	} {
		w := serve(h, withAuth("Bearer "+key))
		if w.Code != 500 || strings.Contains(w.Body.String(), "hunter2") || w.Header().Get("WWW-Authenticate") != "" {
			t.Errorf("%s: got %d %q, challenge %q", name, w.Code, w.Body.String(), w.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestErrorHandler(t *testing.T) {
	f := newFixture(t)
	var got error
	h := httpauth.Require(httpauth.Bearer(f.verifier), httpauth.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
		got = err
		http.Redirect(w, r, "/login", http.StatusFound)
	}))(whoami)
	w := serve(h, withAuth("Bearer "+f.token+"x"))
	if w.Code != http.StatusFound || !errors.Is(got, jwt.ErrInvalidToken) {
		t.Fatalf("got %d, err %v", w.Code, got)
	}
}

func TestSessionCookie(t *testing.T) {
	f := newFixture(t)
	token, s, err := f.sessions.Create(t.Context(), authent.Principal{Subject: "u1", Method: authent.MethodPassword})
	if err != nil {
		t.Fatal(err)
	}
	req := func(method string, body url.Values, cookies ...string) *http.Request {
		var r *http.Request
		if body != nil {
			r = httptest.NewRequest(method, "/", strings.NewReader(body.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			r = httptest.NewRequest(method, "/", nil)
		}
		for _, c := range cookies {
			r.AddCookie(&http.Cookie{Name: "sid", Value: c})
		}
		return r
	}
	withHeader := func(r *http.Request, v string) *http.Request {
		r.Header.Set(httpauth.DefaultCSRFHeader, v)
		return r
	}
	checked := httpauth.Require(httpauth.SessionCookie(f.sessions, "sid"))(whoami)
	unchecked := httpauth.Require(httpauth.SessionCookie(f.sessions, "sid", httpauth.WithCSRFToken(nil)))(whoami)
	optional := httpauth.Optional(httpauth.SessionCookie(f.sessions, "sid"))(whoami)

	cases := []struct {
		name string
		h    http.Handler
		req  *http.Request
		code int
	}{
		{"GET", checked, req("GET", nil, token), 200},
		{"HEAD", checked, req("HEAD", nil, token), 200},
		{"POST without CSRF token", checked, req("POST", nil, token), 403},
		{"POST with wrong CSRF header", checked, withHeader(req("POST", nil, token), s.CSRFToken+"x"), 403},
		{"POST with CSRF header", checked, withHeader(req("POST", nil, token), s.CSRFToken), 200},
		{"POST with CSRF form field", checked, req("POST", url.Values{httpauth.DefaultCSRFField: {s.CSRFToken}}, token), 200},
		{"DELETE without CSRF token", checked, req("DELETE", nil, token), 403},
		{"optional, POST without CSRF token", optional, req("POST", nil, token), 403},
		{"check disabled", unchecked, req("POST", nil, token), 200},
		{"no cookie", checked, req("GET", nil), 401},
		{"invalid cookie", checked, req("GET", nil, "nope"), 401},
		{"two cookies", checked, req("GET", nil, token, token), 401},
		{"optional, no cookie", optional, req("POST", nil), 200},
		{"optional, invalid cookie", optional, req("GET", nil, "nope"), 401},
	}
	for _, c := range cases {
		w := serve(c.h, c.req)
		if w.Code != c.code {
			t.Errorf("%s: got %d, want %d", c.name, w.Code, c.code)
		}
		if w.Code == 200 && len(c.req.CookiesNamed("sid")) > 0 && w.Body.String() != "u1 session" {
			t.Errorf("%s: body %q", c.name, w.Body.String())
		}
		if w.Header().Get("WWW-Authenticate") != "" {
			t.Errorf("%s: unexpected challenge for a cookie", c.name)
		}
	}
}

func TestEmptySubjectIsRejected(t *testing.T) {
	empty := httpauth.AuthenticatorFunc(func(*http.Request) (authent.Principal, error) {
		return authent.Principal{}, nil
	})
	for name, mw := range map[string]func(http.Handler) http.Handler{
		"Require":  httpauth.Require(empty),
		"Optional": httpauth.Optional(empty),
	} {
		if w := serve(mw(whoami), httptest.NewRequest(http.MethodGet, "/", nil)); w.Code != http.StatusInternalServerError {
			t.Errorf("%s: status = %d, want 500", name, w.Code)
		}
	}
}

func TestFromContextWithoutPrincipal(t *testing.T) {
	if _, ok := authent.FromContext(context.Background()); ok {
		t.Fatal("FromContext found a Principal in an empty context")
	}
}
