package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

// userInfoClaims are the claims of a valid signed UserInfo response. They
// have no "exp", which OpenID Connect Core §5.3.2 does not require.
func userInfoClaims(p *fakeProvider) jwt.Claims {
	return jwt.Claims{
		Issuer:   p.URL,
		Subject:  "user-42",
		Audience: jwt.Audience{clientID},
		Extra:    map[string]any{"email": "user42@example.com"},
	}
}

func serveJWT(t *testing.T, signer *jwt.Signer, c jwt.Claims) func(http.ResponseWriter, *http.Request) {
	t.Helper()
	tok, err := signer.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return serveRaw(tok)
}

func serveRaw(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(body))
	}
}

func TestSignedUserInfo(t *testing.T) {
	p := newFakeProvider(t)
	c := newClient(t, p)
	res := login(t, p, c)
	p.userinfo = serveJWT(t, p.signer, userInfoClaims(p))
	info, err := c.UserInfo(context.Background(), res.Token, res.Principal.Subject)
	if err != nil {
		t.Fatalf("UserInfo = %v", err)
	}
	if info.Subject != "user-42" || info.Claims["email"] != "user42@example.com" || info.Claims["iss"] != p.URL {
		t.Fatalf("info = %+v", info)
	}
}

func TestSignedUserInfoRejections(t *testing.T) {
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	impostor, err := jwt.NewSigner(jwt.ES256, otherKey, jwt.WithKeyID("k1"))
	if err != nil {
		t.Fatal(err)
	}
	hmac, err := jwt.NewSigner(jwt.HS256, []byte("a client secret of at least 32 bytes"), jwt.WithKeyID("k1"))
	if err != nil {
		t.Fatal(err)
	}
	type tc struct {
		name    string
		signer  *jwt.Signer // nil: the provider's key
		mutate  func(*jwt.Claims)
		raw     string // served instead of a signed token
		wantJWT error  // nil: only ErrInvalidUserInfo is asserted
	}
	for _, tc := range []tc{
		{name: "wrong issuer", mutate: func(c *jwt.Claims) { c.Issuer = "https://evil.example" }, wantJWT: jwt.ErrInvalidIssuer},
		{name: "missing issuer", mutate: func(c *jwt.Claims) { c.Issuer = "" }, wantJWT: jwt.ErrInvalidIssuer},
		{name: "wrong audience", mutate: func(c *jwt.Claims) { c.Audience = jwt.Audience{"other-client"} }, wantJWT: jwt.ErrInvalidAudience},
		{name: "missing audience", mutate: func(c *jwt.Claims) { c.Audience = nil }, wantJWT: jwt.ErrInvalidAudience},
		{name: "sub mismatch", mutate: func(c *jwt.Claims) { c.Subject = "user-43" }},
		{name: "missing sub", mutate: func(c *jwt.Claims) { c.Subject = "" }},
		{name: "expired", mutate: func(c *jwt.Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-2 * time.Minute)) }, wantJWT: jwt.ErrExpired},
		{name: "foreign key", signer: impostor, wantJWT: jwt.ErrInvalidSignature},
		{name: "HMAC", signer: hmac, wantJWT: jwt.ErrUnsupportedAlgorithm},
		{name: "unsigned", raw: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTQyIn0.", wantJWT: jwt.ErrMalformed},
		{name: "encrypted", raw: "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.a.b.c.d", wantJWT: jwt.ErrMalformed},
		{name: "not a JWT", raw: `{"sub":"user-42"}`, wantJWT: jwt.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t)
			c := newClient(t, p)
			res := login(t, p, c)
			claims := userInfoClaims(p)
			if tc.mutate != nil {
				tc.mutate(&claims)
			}
			signer := p.signer
			if tc.signer != nil {
				signer = tc.signer
			}
			p.userinfo = serveJWT(t, signer, claims)
			if tc.raw != "" {
				p.userinfo = serveRaw(tc.raw)
			}
			info, err := c.UserInfo(context.Background(), res.Token, res.Principal.Subject)
			if info != nil || !errors.Is(err, ErrInvalidUserInfo) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("UserInfo = %+v, %v; want ErrInvalidUserInfo", info, err)
			}
			if tc.wantJWT != nil && !errors.Is(err, tc.wantJWT) {
				t.Fatalf("err = %v, want %v", err, tc.wantJWT)
			}
		})
	}
}

func FuzzUserInfoResponse(f *testing.F) {
	p := newFakeProvider(f)
	c := newClient(f, p)
	signed, err := p.signer.Sign(userInfoClaims(p))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(true, []byte(signed))
	f.Add(false, []byte(`{"sub":"user-42","email":"user42@example.com"}`))
	f.Fuzz(func(t *testing.T, signed bool, body []byte) {
		mediaType := "application/json"
		if signed {
			mediaType = "application/jwt"
		}
		info, err := c.parseUserInfo(context.Background(), mediaType, body, "user-42")
		if err != nil {
			if !errors.Is(err, ErrInvalidUserInfo) {
				t.Fatalf("err = %v, want ErrInvalidUserInfo", err)
			}
			return
		}
		if info.Subject != "user-42" || info.Claims["sub"] != "user-42" {
			t.Fatalf("accepted %+v", info)
		}
	})
}
