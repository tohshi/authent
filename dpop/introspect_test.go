package dpop

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

const (
	rsClientID     = "rs:1"
	rsClientSecret = "s3cret/+"
)

// fakeIntrospection is an RFC 7662 introspection endpoint that answers
// with responses[token], or {"active":false} for unknown tokens.
func fakeIntrospection(t *testing.T, responses map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		if !ok || id != rsClientID || secret != rsClientSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
			r.PostFormValue("token_type_hint") != "access_token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, ok := responses[r.PostFormValue("token")]
		if !ok {
			body = `{"active":false}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func introspectionConfig(endpoint string) IntrospectionConfig {
	return IntrospectionConfig{
		Endpoint:          endpoint,
		ClientID:          rsClientID,
		ClientSecret:      rsClientSecret,
		Issuer:            issuer,
		Audiences:         []string{"api"},
		ConfirmationClaim: true,
		Now:               func() time.Time { return testNow },
	}
}

func newIntrospector(t *testing.T, cfg IntrospectionConfig) *Introspector {
	t.Helper()
	in, err := NewIntrospector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func introspectionResponse(t *testing.T, edit func(m map[string]any)) string {
	t.Helper()
	m := map[string]any{
		"active": true,
		"sub":    "user-1",
		"iss":    issuer,
		"aud":    "api",
		"scope":  "read write",
		"exp":    testNow.Add(5 * time.Minute).Unix(),
		"cnf":    map[string]any{"jkt": "placeholder"},
	}
	if edit != nil {
		edit(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIntrospectionAuthenticator(t *testing.T) {
	ctx := context.Background()
	p := newProver(t)
	bound := func(edit func(map[string]any)) string {
		return introspectionResponse(t, func(m map[string]any) {
			m["cnf"] = map[string]any{"jkt": p.Thumbprint()}
			if edit != nil {
				edit(m)
			}
		})
	}
	srv := fakeIntrospection(t, map[string]string{
		"good":          bound(nil),
		"inactive":      bound(func(m map[string]any) { m["active"] = false }),
		"unbound":       bound(func(m map[string]any) { delete(m, "cnf") }),
		"cnf no jkt":    bound(func(m map[string]any) { m["cnf"] = map[string]any{"x5t#S256": "abc"} }),
		"expired":       bound(func(m map[string]any) { m["exp"] = testNow.Add(-time.Minute).Unix() }),
		"not yet valid": bound(func(m map[string]any) { m["nbf"] = testNow.Add(time.Minute).Unix() }),
		"other aud":     bound(func(m map[string]any) { m["aud"] = []string{"other"} }),
		"no aud":        bound(func(m map[string]any) { delete(m, "aud") }),
		"other iss":     bound(func(m map[string]any) { m["iss"] = "https://evil.example" }),
		"scope array":   bound(func(m map[string]any) { m["scope"] = []string{"read"} }),
		"no sub":        bound(func(m map[string]any) { delete(m, "sub") }),
	})
	a, err := NewAuthenticator(newIntrospector(t, introspectionConfig(srv.URL)), newVerifier(t))
	if err != nil {
		t.Fatal(err)
	}
	request := func(prover *Prover, tok string) Request {
		proof, err := prover.Proof("GET", resourceURL, tok)
		if err != nil {
			t.Fatal(err)
		}
		return Request{Method: "GET", URL: resourceURL, Proofs: []string{proof}, AccessToken: tok}
	}

	principal, err := a.Authenticate(ctx, request(p, "good"))
	if err != nil {
		t.Fatalf("Authenticate = %v", err)
	}
	if principal.Subject != "user-1" || principal.Issuer != issuer || principal.Method != authent.MethodDPoP ||
		principal.Claims["scope"] != "read write" {
		t.Fatalf("principal = %+v", principal)
	}

	for name, tc := range map[string]struct {
		r    Request
		want error
	}{
		"stolen token, attacker's key": {request(newProver(t), "good"), ErrKeyBinding},
		"proof for another token":      {Request{Method: "GET", URL: resourceURL, Proofs: request(p, "other").Proofs, AccessToken: "good"}, ErrInvalidProof},
		"unknown token":                {request(p, "unknown"), ErrInactiveToken},
		"inactive":                     {request(p, "inactive"), ErrInactiveToken},
		"unbound token":                {request(p, "unbound"), ErrKeyBinding},
		"cnf without jkt":              {request(p, "cnf no jkt"), ErrKeyBinding},
		"expired":                      {request(p, "expired"), ErrInactiveToken},
		"not yet valid":                {request(p, "not yet valid"), ErrInactiveToken},
		"other audience":               {request(p, "other aud"), ErrInactiveToken},
		"no audience":                  {request(p, "no aud"), ErrInactiveToken},
		"other issuer":                 {request(p, "other iss"), ErrInactiveToken},
		"scope not a string":           {request(p, "scope array"), ErrInactiveToken},
		"no subject":                   {request(p, "no sub"), jwt.ErrMissingClaim},
		"no token":                     {Request{Method: "GET", URL: resourceURL}, ErrNoToken},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := a.Authenticate(ctx, tc.r)
			if !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestIntrospectorRejectsBoundTokenAsBearer(t *testing.T) {
	srv := fakeIntrospection(t, map[string]string{"bound": introspectionResponse(t, nil)})
	cfg := introspectionConfig(srv.URL)
	cfg.ConfirmationClaim = false
	_, err := newIntrospector(t, cfg).Verify(context.Background(), "bound")
	if !errors.Is(err, jwt.ErrSenderConstrained) {
		t.Fatalf("err = %v, want jwt.ErrSenderConstrained", err)
	}
}

func TestIntrospectorAnyAudience(t *testing.T) {
	srv := fakeIntrospection(t, map[string]string{"t": introspectionResponse(t, func(m map[string]any) { delete(m, "aud") })})
	cfg := introspectionConfig(srv.URL)
	cfg.Audiences, cfg.AnyAudience = nil, true
	if _, err := newIntrospector(t, cfg).Verify(context.Background(), "t"); err != nil {
		t.Fatalf("Verify = %v", err)
	}
}

func TestIntrospectorServerFailures(t *testing.T) {
	big := `{"active":true,"x":"` + strings.Repeat("a", 1<<20) + `"}`
	srv := fakeIntrospection(t, map[string]string{
		"not json":         "<html>",
		"no active":        `{"sub":"user-1"}`,
		"string active":    `{"active":"true"}`,
		"duplicate active": `{"active":false,"active":true}`,
		"too large":        big,
	})
	cfg := introspectionConfig(srv.URL)
	cases := map[string]struct {
		cfg   IntrospectionConfig
		token string
	}{
		"not json":           {cfg, "not json"},
		"no active":          {cfg, "no active"},
		"string active":      {cfg, "string active"},
		"duplicate active":   {cfg, "duplicate active"},
		"too large":          {cfg, "too large"},
		"wrong client creds": {func() IntrospectionConfig { c := cfg; c.ClientSecret = "wrong"; return c }(), "good"},
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	unreachable := cfg
	unreachable.Endpoint = closed.URL
	cases["unreachable"] = struct {
		cfg   IntrospectionConfig
		token string
	}{unreachable, "good"}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := newIntrospector(t, tc.cfg).Verify(context.Background(), tc.token)
			if err == nil || errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v, want a server error that is not ErrUnauthenticated", err)
			}
		})
	}
}

func TestNewIntrospectorRequiresConfig(t *testing.T) {
	good := introspectionConfig("https://as.example.com/introspect")
	for name, edit := range map[string]func(*IntrospectionConfig){
		"no endpoint":       func(c *IntrospectionConfig) { c.Endpoint = "" },
		"relative endpoint": func(c *IntrospectionConfig) { c.Endpoint = "/introspect" },
		"no client id":      func(c *IntrospectionConfig) { c.ClientID = "" },
		"no client secret":  func(c *IntrospectionConfig) { c.ClientSecret = "" },
		"no audience":       func(c *IntrospectionConfig) { c.Audiences = nil },
	} {
		cfg := good
		edit(&cfg)
		if _, err := NewIntrospector(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzIntrospectionResponse(f *testing.F) {
	f.Add([]byte(`{"active":true,"aud":"api","exp":1780315500,"cnf":{"jkt":"x"}}`))
	f.Add([]byte(`{"active":false}`))
	f.Add([]byte(`{"active":true,"aud":["api"],"scope":"a b","nbf":1}`))
	in, err := NewIntrospector(introspectionConfig("https://as.example.com/introspect"))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		c, err := in.parse(body)
		if err != nil {
			return
		}
		if c.Extra["active"] != true || !slices.Contains(c.Audience, "api") {
			t.Fatalf("accepted %s", body)
		}
	})
}
