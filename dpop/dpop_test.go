package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

const (
	resourceURL = "https://api.example.com/v1/items"
	accessTok   = "access-token-1"
)

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newProver(t testing.TB) *Prover {
	t.Helper()
	p, err := NewProver(jwt.ES256, newKey(t), WithProverClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newVerifier(t testing.TB, opts ...Option) *Verifier {
	t.Helper()
	base := []Option{
		WithAlgorithms(jwt.ES256, jwt.EdDSA),
		WithReplayCache(jwt.NewMemoryReplayCache()),
		WithClock(func() time.Time { return testNow }),
	}
	v, err := NewVerifier(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// RFC 9449 Figures 5 and 13: proofs made by an independent implementation.
const (
	rfcTokenProof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik" +
		"VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR" +
		"nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE" +
		"QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj" +
		"oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia" +
		"WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg" +
		"4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
	rfcResourceProof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik" +
		"VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR" +
		"nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE" +
		"QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj" +
		"oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z" +
		"WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF" +
		"c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E" +
		"OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"
	rfcAccessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
	rfcJKT         = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
)

func TestRFC9449Vectors(t *testing.T) {
	ctx := context.Background()
	at := func(unix int64) Option { return WithClock(func() time.Time { return time.Unix(unix, 0) }) }

	v := newVerifier(t, at(1562262618+5))
	p, err := v.Verify(ctx, Request{
		Method:      "GET",
		URL:         "https://resource.example.org/protectedresource",
		Proofs:      []string{rfcResourceProof},
		AccessToken: rfcAccessToken,
		JKT:         rfcJKT,
	})
	if err != nil {
		t.Fatalf("resource proof: %v", err)
	}
	if p.JKT != rfcJKT || p.ID != "e1j3V_bKic8-LAEB" || p.IssuedAt.Unix() != 1562262618 {
		t.Fatalf("proof = %+v", p)
	}

	v = newVerifier(t, at(1562262616))
	if _, err := v.Verify(ctx, Request{Method: "POST", URL: "https://server.example.com/token", Proofs: []string{rfcTokenProof}}); err != nil {
		t.Fatalf("token proof: %v", err)
	}

	if got := AccessTokenHash(rfcAccessToken); got != "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo" {
		t.Fatalf("ath = %s", got)
	}
}

func TestProverRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := newProver(t)
	p.SetNonce("https://api.example.com/other", "n-1")
	p.SetNonce("https://as.example.com/token", "n-as")
	proof, err := p.Proof("GET", resourceURL+"?page=2#frag", accessTok)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := jwt.VerifyWithEmbeddedKey(proof, jwt.ES256)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(jws.Payload, &c)
	if c["htu"] != resourceURL || c["htm"] != "GET" || c["nonce"] != "n-1" || c["ath"] != AccessTokenHash(accessTok) {
		t.Fatalf("claims = %v", c)
	}
	if jti, _ := c["jti"].(string); len(jti) < 16 {
		t.Fatalf("jti = %q", jti)
	}

	v := newVerifier(t, WithNonce(func(_ context.Context, n string) bool { return n == "n-1" }))
	got, err := v.Verify(ctx, Request{Method: "GET", URL: resourceURL, Proofs: []string{proof}, AccessToken: accessTok, JKT: p.Thumbprint()})
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if got.JKT != p.Thumbprint() || got.Nonce != "n-1" {
		t.Fatalf("proof = %+v", got)
	}

	a, _ := p.Proof("GET", resourceURL, "")
	b, _ := p.Proof("GET", resourceURL, "")
	if a == b {
		t.Fatal("proofs are not unique")
	}
	if _, err := NewProver(jwt.HS256, []byte(strings.Repeat("k", 32))); err == nil {
		t.Fatal("HMAC prover created")
	}
}

func TestVerifyRejections(t *testing.T) {
	ctx := context.Background()
	key := newKey(t)
	p, _ := NewProver(jwt.ES256, key, WithProverClock(func() time.Time { return testNow }))
	sign := func(typ string, claims map[string]any) string {
		s, err := jwt.NewSigner(jwt.ES256, key, jwt.WithType(typ), jwt.WithJWKHeader())
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(claims)
		tok, err := s.SignPayload(b)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	claims := func(mut func(map[string]any)) map[string]any {
		c := map[string]any{"jti": "j1", "htm": "GET", "htu": resourceURL, "iat": testNow.Unix(), "ath": AccessTokenHash(accessTok)}
		if mut != nil {
			mut(c)
		}
		return c
	}
	good, _ := p.Proof("GET", resourceURL, accessTok)
	other := newProver(t)
	hmacSigner, _ := jwt.NewSigner(jwt.HS256, []byte(strings.Repeat("k", 32)), jwt.WithType("dpop+jwt"))
	hmacProof, _ := hmacSigner.SignPayload([]byte(`{}`))
	rs, _ := jwt.NewSigner(jwt.ES384, func() *ecdsa.PrivateKey {
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return k
	}(), jwt.WithType("dpop+jwt"), jwt.WithJWKHeader())
	es384Proof, _ := rs.SignPayload([]byte(`{}`))

	base := Request{Method: "GET", URL: resourceURL, AccessToken: accessTok}
	tests := []struct {
		name string
		mut  func(r *Request)
		want error
	}{
		{"no header", func(r *Request) { r.Proofs = nil }, ErrInvalidProof},
		{"two headers", func(r *Request) { r.Proofs = []string{good, good} }, ErrInvalidProof},
		{"not a JWT", func(r *Request) { r.Proofs = []string{"nope"} }, jwt.ErrMalformed},
		{"HMAC proof", func(r *Request) { r.Proofs = []string{hmacProof} }, jwt.ErrUnsupportedAlgorithm},
		{"alg not allowed", func(r *Request) { r.Proofs = []string{es384Proof} }, jwt.ErrUnsupportedAlgorithm},
		{"wrong typ", func(r *Request) { r.Proofs = []string{sign("JWT", claims(nil))} }, ErrInvalidProof},
		{"missing jti", func(r *Request) {
			r.Proofs = []string{sign("dpop+jwt", claims(func(c map[string]any) { delete(c, "jti") }))}
		}, ErrInvalidProof},
		{"missing iat", func(r *Request) {
			r.Proofs = []string{sign("dpop+jwt", claims(func(c map[string]any) { delete(c, "iat") }))}
		}, ErrInvalidProof},
		{"htm as number", func(r *Request) {
			r.Proofs = []string{sign("dpop+jwt", claims(func(c map[string]any) { c["htm"] = 1 }))}
		}, ErrInvalidProof},
		{"method mismatch", func(r *Request) { r.Method = "POST" }, ErrInvalidProof},
		{"method case", func(r *Request) { r.Method = "get" }, ErrInvalidProof},
		{"other path", func(r *Request) { r.URL = "https://api.example.com/v1/admin" }, ErrInvalidProof},
		{"other host", func(r *Request) { r.URL = "https://evil.example.com/v1/items" }, ErrInvalidProof},
		{"other scheme", func(r *Request) { r.URL = "http://api.example.com/v1/items" }, ErrInvalidProof},
		{"htu not absolute", func(r *Request) {
			r.Proofs = []string{sign("dpop+jwt", claims(func(c map[string]any) { c["htu"] = "/v1/items" }))}
		}, ErrInvalidProof},
		{"too old", func(r *Request) {
			r.Proofs = []string{sign("dpop+jwt", claims(func(c map[string]any) { c["iat"] = testNow.Add(-DefaultMaxAge - time.Second).Unix() }))}
		}, ErrInvalidProof},
		{"from the future", func(r *Request) {
			r.Proofs = []string{sign("dpop+jwt", claims(func(c map[string]any) { c["iat"] = testNow.Add(DefaultLeeway + time.Second).Unix() }))}
		}, ErrInvalidProof},
		{"missing ath", func(r *Request) {
			r.Proofs = []string{sign("dpop+jwt", claims(func(c map[string]any) { delete(c, "ath") }))}
		}, ErrInvalidProof},
		{"other access token", func(r *Request) { r.AccessToken = "access-token-2" }, ErrInvalidProof},
		{"key not bound to token", func(r *Request) { r.JKT = other.Thumbprint() }, ErrKeyBinding},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.Proofs = []string{good}
			tc.mut(&r)
			_, err := newVerifier(t).Verify(ctx, r)
			if !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyAcceptsWindowEdgesAndQuery(t *testing.T) {
	ctx := context.Background()
	for name, iat := range map[string]time.Time{
		"oldest":  testNow.Add(-DefaultMaxAge),
		"leeway":  testNow.Add(DefaultLeeway),
		"current": testNow,
	} {
		p, _ := NewProver(jwt.ES256, newKey(t), WithProverClock(func() time.Time { return iat }))
		proof, _ := p.Proof("GET", resourceURL, "")
		r := Request{Method: "GET", URL: resourceURL + "?q=1", Proofs: []string{proof}}
		if _, err := newVerifier(t).Verify(ctx, r); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReplay(t *testing.T) {
	ctx := context.Background()
	p := newProver(t)
	proof, _ := p.Proof("GET", resourceURL, "")
	r := Request{Method: "GET", URL: resourceURL, Proofs: []string{proof}}

	v := newVerifier(t)
	if _, err := v.Verify(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, r); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay: err = %v", err)
	}

	// A proof rejected for another reason is not recorded.
	v = newVerifier(t)
	if _, err := v.Verify(ctx, Request{Method: "POST", URL: resourceURL, Proofs: []string{proof}}); !errors.Is(err, ErrInvalidProof) {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, r); err != nil {
		t.Fatalf("after rejected attempt: %v", err)
	}

	noReplay, _ := NewVerifier(WithAlgorithms(jwt.ES256), WithoutReplayCheck(), WithClock(func() time.Time { return testNow }))
	for range 2 {
		if _, err := noReplay.Verify(ctx, r); err != nil {
			t.Fatalf("WithoutReplayCheck: %v", err)
		}
	}
}

type failingCache struct{}

func (failingCache) Add(context.Context, string, time.Duration) (bool, error) {
	return false, errors.New("store down")
}

func TestReplayCacheFailureFailsClosed(t *testing.T) {
	v, _ := NewVerifier(WithAlgorithms(jwt.ES256), WithReplayCache(failingCache{}), WithClock(func() time.Time { return testNow }))
	proof, _ := newProver(t).Proof("GET", resourceURL, "")
	_, err := v.Verify(context.Background(), Request{Method: "GET", URL: resourceURL, Proofs: []string{proof}})
	if err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("err = %v, want an infrastructure error", err)
	}
}

func TestNonce(t *testing.T) {
	ctx := context.Background()
	v := newVerifier(t, WithNonce(func(_ context.Context, n string) bool { return n == "good" }))
	p := newProver(t)
	for name, nonce := range map[string]string{"missing": "", "stale": "old"} {
		if nonce != "" {
			p.SetNonce(resourceURL, nonce)
		}
		proof, _ := p.Proof("GET", resourceURL, "")
		_, err := v.Verify(ctx, Request{Method: "GET", URL: resourceURL, Proofs: []string{proof}})
		if !errors.Is(err, ErrUseNonce) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	p.SetNonce(resourceURL, "good")
	proof, _ := p.Proof("GET", resourceURL, "")
	if _, err := v.Verify(ctx, Request{Method: "GET", URL: resourceURL, Proofs: []string{proof}}); err != nil {
		t.Fatal(err)
	}
	p.SetNonce(resourceURL, "bad nonce") // not 1*NQCHAR; ignored
	if p.nonce("https://api.example.com") != "good" {
		t.Fatal("invalid nonce stored")
	}
}

func TestNormalizeURI(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://server.example.com/token", "https://server.example.com/token"},
		{"HTTPS://Server.Example.COM:443/token", "https://server.example.com/token"},
		{"https://server.example.com", "https://server.example.com/"},
		{"http://server.example.com:80/a", "http://server.example.com/a"},
		{"https://server.example.com:8443/a", "https://server.example.com:8443/a"},
		{"https://server.example.com/a/./b/../c", "https://server.example.com/a/c"},
		{"https://server.example.com/a/b/..", "https://server.example.com/a/"},
		{"https://server.example.com/%7euser/%2fx%2F", "https://server.example.com/~user/%2Fx%2F"},
		{"https://server.example.com/a?b=c#d", "https://server.example.com/a"},
		{"https://[2001:DB8::1]:443/a", "https://[2001:db8::1]/a"},
	} {
		got, err := normalizeURI(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("normalizeURI(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"/token", "ftp://server.example.com/", "https://user@server.example.com/", "https:opaque", ""} {
		if _, err := normalizeURI(bad); err == nil {
			t.Errorf("normalizeURI(%q) succeeded", bad)
		}
	}
}

func TestAccessToken(t *testing.T) {
	for in, want := range map[string]string{
		"DPoP " + rfcAccessToken: rfcAccessToken,
		"dpop  abc==":            "abc==",
	} {
		if got, err := AccessToken(in); err != nil || got != want {
			t.Errorf("AccessToken(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "Bearer abc", "DPoP", "DPoP ", "DPoP a b", "DPoP ==", "DPoPabc"} {
		if _, err := AccessToken(in); !errors.Is(err, ErrNoToken) {
			t.Errorf("AccessToken(%q) err = %v", in, err)
		}
	}
}

func TestChallenge(t *testing.T) {
	v := newVerifier(t)
	for err, want := range map[error]string{
		nil:                         `DPoP algs="ES256 EdDSA"`,
		ErrNoToken:                  `DPoP algs="ES256 EdDSA"`,
		ErrUseNonce:                 `DPoP error="use_dpop_nonce", algs="ES256 EdDSA"`,
		ErrReplayed:                 `DPoP error="invalid_dpop_proof", algs="ES256 EdDSA"`,
		ErrKeyBinding:               `DPoP error="invalid_token", algs="ES256 EdDSA"`,
		jwt.ErrExpired:              `DPoP error="invalid_token", algs="ES256 EdDSA"`,
		errors.New("database down"): `DPoP algs="ES256 EdDSA"`,
	} {
		if got := v.Challenge(err); got != want {
			t.Errorf("Challenge(%v) = %s, want %s", err, got, want)
		}
	}
}

func TestNewVerifierRequiresPolicy(t *testing.T) {
	cache := WithReplayCache(jwt.NewMemoryReplayCache())
	for name, opts := range map[string][]Option{
		"no algorithms":     {cache},
		"HMAC":              {WithAlgorithms(jwt.HS256), cache},
		"none":              {WithAlgorithms("none"), cache},
		"no replay policy":  {WithAlgorithms(jwt.ES256)},
		"both replay modes": {WithAlgorithms(jwt.ES256), cache, WithoutReplayCheck()},
		"zero max age":      {WithAlgorithms(jwt.ES256), cache, WithMaxAge(0)},
		"negative leeway":   {WithAlgorithms(jwt.ES256), cache, WithLeeway(-time.Second)},
	} {
		if _, err := NewVerifier(opts...); err == nil {
			t.Errorf("%s: NewVerifier succeeded", name)
		}
	}
}
