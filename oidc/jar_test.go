package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent/jwt"
)

// openRequestObject verifies a request object as the provider would and
// returns the authorization request parameters it carries.
func (p *fakeProvider) openRequestObject(raw, clientIDParam string) (url.Values, error) {
	if p.requestObjects == nil {
		return nil, errors.New("request objects are not accepted")
	}
	claims, err := p.requestObjects.Verify(context.Background(), raw)
	if err != nil {
		return nil, err
	}
	if claims.NotBefore.IsZero() || claims.ExpiresAt.Sub(claims.NotBefore.Time) > time.Hour {
		return nil, errors.New("nbf missing or lifetime over an hour")
	}
	params := url.Values{}
	for name, v := range claims.Extra {
		switch v := v.(type) {
		case string:
			params.Set(name, v)
		case float64:
			params.Set(name, strconv.FormatFloat(v, 'f', -1, 64))
		default:
			b, _ := json.Marshal(v)
			params.Set(name, string(b))
		}
	}
	if params.Get("client_id") != clientIDParam {
		return nil, errors.New("client_id differs from the request object's")
	}
	return params, nil
}

// decodeJWS returns the header and claims of a compact JWS without
// verifying it.
func decodeJWS(t *testing.T, raw string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", raw)
	}
	for i, out := range []*map[string]any{&header, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatal(err)
		}
	}
	return header, claims
}

func TestJARByValue(t *testing.T) {
	for name, withProver := range map[string]bool{"plain": false, "DPoP": true} {
		t.Run(name, func(t *testing.T) {
			p := newFakeProvider(t)
			p.requireJAR = true
			p.requestAlgs = []string{"ES256"}
			p.mutate = func(c *jwt.Claims) { c.Extra["auth_time"] = now.Unix() }
			mods := []func(*Config){withPrivateKeyJWT(t, p), func(c *Config) { c.JAR = true }}
			prover := newProver(t)
			if withProver {
				mods = append(mods, withDPoP(prover))
			}
			c := newClient(t, p, mods...)
			req, err := c.AuthCodeURL(maxAge5m, oauth2.SetAuthURLParam("prompt", "login"))
			if err != nil {
				t.Fatal(err)
			}
			if !req.Expiry.Equal(now.Add(5 * time.Minute)) {
				t.Fatalf("Expiry = %v", req.Expiry)
			}
			u, _ := url.Parse(req.URL)
			q := u.Query()
			if keys := slices.Sorted(maps.Keys(q)); !slices.Equal(keys, []string{"client_id", "request", "response_type", "scope"}) {
				t.Fatalf("authorization URL carries %v", keys)
			}
			header, claims := decodeJWS(t, q.Get("request"))
			if header["typ"] != "oauth-authz-req+jwt" || header["alg"] != "ES256" {
				t.Fatalf("header = %v", header)
			}
			unix := float64(now.Unix())
			for k, want := range map[string]any{
				"iss": clientID, "aud": p.URL, "iat": unix, "nbf": unix, "exp": unix + 300,
				"client_id": clientID, "response_type": "code", "redirect_uri": redirectURL,
				"scope": "openid email", "state": req.State, "nonce": req.Nonce,
				"code_challenge_method": "S256", "prompt": "login", "max_age": float64(300),
			} {
				if claims[k] != want {
					t.Errorf("claim %s = %v, want %v", k, claims[k], want)
				}
			}
			if jti, _ := claims["jti"].(string); len(jti) < 22 {
				t.Errorf("jti = %q", jti)
			}
			if withProver && claims["dpop_jkt"] != prover.Thumbprint() {
				t.Errorf("dpop_jkt = %v", claims["dpop_jkt"])
			}

			state, code := p.authorize(t, req.URL)
			if _, err := c.Exchange(context.Background(), req, state, code); err != nil {
				t.Fatalf("Exchange = %v", err)
			}
		})
	}
}

func TestJARPushed(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.par, p.requireJAR = true, true
	c := newClient(t, p, withPrivateKeyJWT(t, p), func(c *Config) { c.JAR = true })
	req, err := c.PushAuthCodeURL(ctx, acrMFAOrHW)
	if err != nil {
		t.Fatalf("PushAuthCodeURL = %v", err)
	}
	form := p.lastPush.PostForm
	if keys := slices.Sorted(maps.Keys(form)); !slices.Equal(keys, []string{"client_assertion", "client_assertion_type", "client_id", "request"}) {
		t.Fatalf("pushed form carries %v", keys)
	}
	if _, claims := decodeJWS(t, form.Get("request")); claims["acr_values"] != "urn:example:mfa urn:example:hwk" {
		t.Fatalf("request object = %v", claims)
	}
	if !req.Expiry.Equal(now.Add(time.Minute)) {
		t.Fatalf("Expiry = %v, want the pushed request's", req.Expiry)
	}
	p.mutate = func(c *jwt.Claims) { c.Extra["acr"] = "urn:example:mfa" }
	state, code := p.authorize(t, req.URL)
	if _, err := c.Exchange(ctx, req, state, code); err != nil {
		t.Fatalf("Exchange = %v", err)
	}
}

func TestJARClaimsParameter(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p, withPrivateKeyJWT(t, p), func(c *Config) { c.JAR = true })
	req, err := c.AuthCodeURL(oauth2.SetAuthURLParam("claims", `{"id_token":{"acr":{"essential":true}}}`))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(req.URL)
	_, claims := decodeJWS(t, u.Query().Get("request"))
	if _, ok := claims["claims"].(map[string]any); !ok {
		t.Fatalf("claims = %#v, want a JSON object", claims["claims"])
	}
}

func TestJARRejectsUnsignableRequests(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.par = true
	c := newClient(t, p, withPrivateKeyJWT(t, p), func(c *Config) { c.JAR = true })
	for name, opt := range map[string]oauth2.AuthCodeOption{
		"registered claim name": oauth2.SetAuthURLParam("iss", "https://evil.example"),
		"request":               oauth2.SetAuthURLParam("request", "x"),
		"request_uri":           oauth2.SetAuthURLParam("request_uri", "urn:x"),
		"claims not JSON":       oauth2.SetAuthURLParam("claims", "acr"),
		"claims not an object":  oauth2.SetAuthURLParam("claims", "[]"),
	} {
		if req, err := c.AuthCodeURL(opt); err == nil {
			t.Errorf("%s: AuthCodeURL = %s", name, req.URL)
		}
		if req, err := c.PushAuthCodeURL(ctx, opt); err == nil {
			t.Errorf("%s: PushAuthCodeURL = %s", name, req.URL)
		}
	}
}

func TestJARConfigValidation(t *testing.T) {
	p := newFakeProvider(t)
	jar := func(c *Config) { c.JAR = true }
	pkjwt := withPrivateKeyJWT(t, p)
	for _, tc := range []struct {
		name     string
		provider func(*Provider)
		mods     []func(*Config)
	}{
		{"JAR without a client key", nil, []func(*Config){jar}},
		{"unsupported algorithm", func(m *Provider) { m.RequestObjectSigningAlgValuesSupported = []string{"RS256"} }, []func(*Config){pkjwt, jar}},
		{"provider requires JAR", func(m *Provider) { m.RequireSignedRequestObject = true }, []func(*Config){pkjwt}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta, err := Discover(context.Background(), p.URL, p.Client())
			if err != nil {
				t.Fatal(err)
			}
			if tc.provider != nil {
				tc.provider(meta)
			}
			cfg := Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL}
			for _, mod := range tc.mods {
				mod(&cfg)
			}
			if _, err := NewClient(meta, cfg); err == nil {
				t.Fatal("NewClient accepted the configuration")
			}
		})
	}
}
