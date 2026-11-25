package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/json/v2"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

var (
	testNow    = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	testClock  = func() time.Time { return testNow }
	testIssuer = "https://issuer.example"
)

var (
	keysOnce sync.Once
	rsaKey   *rsa.PrivateKey
	p256Key  *ecdsa.PrivateKey
	p384Key  *ecdsa.PrivateKey
	p521Key  *ecdsa.PrivateKey
	edKey    ed25519.PrivateKey
	hmacKey  = []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
)

func loadKeys(t testing.TB) {
	t.Helper()
	keysOnce.Do(func() {
		var err error
		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		p256Key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		p384Key, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		p521Key, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		_, edKey, _ = ed25519.GenerateKey(rand.Reader)
	})
}

func signingKeyFor(t testing.TB, alg Algorithm) any {
	loadKeys(t)
	switch alg {
	case HS256, HS384, HS512:
		return hmacKey
	case RS256, RS384, RS512, PS256, PS384, PS512:
		return rsaKey
	case ES256:
		return p256Key
	case ES384:
		return p384Key
	case ES512:
		return p521Key
	case EdDSA:
		return edKey
	}
	t.Fatalf("no key for %s", alg)
	return nil
}

var allAlgs = []Algorithm{HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

func validClaims() Claims {
	return Claims{
		Issuer:    testIssuer,
		Subject:   "alice",
		Audience:  Audience{"api"},
		ExpiresAt: NewNumericDate(testNow.Add(time.Hour)),
		IssuedAt:  NewNumericDate(testNow.Add(-time.Minute)),
		Extra:     map[string]any{"scope": "read write"},
	}
}

func newVerifier(t testing.TB, ks KeySet, opts ...VerifierOption) *Verifier {
	t.Helper()
	base := []VerifierOption{WithAlgorithms(allAlgs...), WithIssuer(testIssuer), WithAudience("api"), WithClock(testClock)}
	v, err := NewVerifier(ks, append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustSign(t testing.TB, alg Algorithm, c Claims, opts ...SignerOption) (string, *Signer) {
	t.Helper()
	s, err := NewSigner(alg, signingKeyFor(t, alg), opts...)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return tok, s
}

func TestRoundTripAllAlgorithms(t *testing.T) {
	for _, alg := range allAlgs {
		t.Run(string(alg), func(t *testing.T) {
			tok, s := mustSign(t, alg, validClaims(), WithKeyID("k1"))
			v := newVerifier(t, NewStaticKeySet(s.VerificationKey()))
			c, err := v.Verify(context.Background(), tok)
			if err != nil {
				t.Fatalf("Verify = %v", err)
			}
			if c.Subject != "alice" || c.Extra["scope"] != "read write" {
				t.Fatalf("unexpected claims %+v", c)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	c := validClaims()
	c.Extra["auth_time"] = float64(testNow.Add(-2 * time.Hour).Unix())
	tok, s := mustSign(t, ES256, c)
	v := newVerifier(t, NewStaticKeySet(s.VerificationKey()))
	p, err := v.Authenticate(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "alice" || p.Issuer != testIssuer || p.Method != authent.MethodJWT {
		t.Fatalf("unexpected principal %+v", p)
	}
	if !p.AuthTime.Equal(testNow.Add(-2 * time.Hour)) {
		t.Fatalf("AuthTime = %v", p.AuthTime)
	}
	if p.Claims["sub"] != "alice" || p.Claims["scope"] != "read write" {
		t.Fatalf("Claims = %v", p.Claims)
	}

	c = validClaims()
	c.Subject = ""
	tok, _ = mustSign(t, ES256, c)
	if _, err := v.Authenticate(context.Background(), tok); !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("missing sub: err = %v", err)
	}
}

// RFC 7515 Appendix A.1.
func TestRFC7515HS256Vector(t *testing.T) {
	key, err := b64.DecodeString("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
	if err != nil {
		t.Fatal(err)
	}
	token := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
		".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	jwk, err := NewHMACKey("", HS256, key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(NewStaticKeySet(jwk), WithAlgorithms(HS256), WithIssuer("joe"), WithAnyAudience(),
		WithClock(func() time.Time { return time.Unix(1300819380-60, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if c.Extra["http://example.com/is_root"] != true {
		t.Fatalf("claims = %+v", c)
	}
}

// RFC 8037 Appendix A.4 and A.5.
func TestRFC8037Ed25519Vector(t *testing.T) {
	d, _ := b64.DecodeString("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
	priv := ed25519.NewKeyFromSeed(d)
	pubJWK, err := ParseJWK([]byte(`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pubJWK.Key.(ed25519.PublicKey)) {
		t.Fatal("public key does not match private key")
	}
	input := "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	want := "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	sig, err := sign(EdDSA, priv, []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if got := b64.EncodeToString(sig); got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
	c, err := parseCompact(input+"."+want, DefaultMaxTokenSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(EdDSA, pubJWK.Key, []byte(c.signingInput), c.signature); err != nil {
		t.Fatal(err)
	}
}

// Vectors generated by testdata/gen_openssl_vectors.py with the openssl CLI.
func TestOpenSSLVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/openssl_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Alg   Algorithm      `json:"alg"`
			JWK   map[string]any `json:"jwk"`
			Token string         `json:"token"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) != 10 {
		t.Fatalf("got %d vectors", len(file.Vectors))
	}
	for _, vec := range file.Vectors {
		t.Run(string(vec.Alg), func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"keys": []any{vec.JWK}})
			set, err := ParseJWKSet(raw)
			if err != nil || len(set.Keys) != 1 {
				t.Fatalf("ParseJWKSet = %v, %d keys", err, len(set.Keys))
			}
			v := newVerifier(t, NewStaticKeySet(set.Keys...))
			if _, err := v.Verify(context.Background(), vec.Token); err != nil {
				t.Fatalf("Verify = %v", err)
			}
			// Our JWK encoding must round-trip to the same members.
			enc, _ := json.Marshal(set.Keys[0])
			var got map[string]any
			_ = json.Unmarshal(enc, &got)
			for k, want := range vec.JWK {
				if got[k] != want {
					t.Errorf("member %s = %v, want %v", k, got[k], want)
				}
			}
		})
	}
}

func encodeSegments(t testing.TB, header, payload any) string {
	t.Helper()
	enc := func(v any) string {
		if s, ok := v.(string); ok {
			return b64.EncodeToString([]byte(s))
		}
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b64.EncodeToString(b)
	}
	return enc(header) + "." + enc(payload)
}

// forge signs arbitrary header and payload with key using alg.
func forge(t testing.TB, alg Algorithm, key any, header, payload any) string {
	t.Helper()
	input := encodeSegments(t, header, payload)
	sig, err := sign(alg, key, []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64.EncodeToString(sig)
}

func validPayload() map[string]any {
	return map[string]any{"iss": testIssuer, "sub": "alice", "aud": "api", "exp": testNow.Add(time.Hour).Unix()}
}

func TestRejections(t *testing.T) {
	loadKeys(t)
	rsaJWK := JWK{KeyID: "rsa", Key: &rsaKey.PublicKey}
	ecJWK := JWK{KeyID: "ec", Key: &p256Key.PublicKey}
	v := newVerifier(t, NewStaticKeySet(rsaJWK, ecJWK))
	ctx := context.Background()

	good := forge(t, RS256, rsaKey, map[string]any{"alg": "RS256", "kid": "rsa"}, validPayload())
	if _, err := v.Verify(ctx, good); err != nil {
		t.Fatalf("baseline token rejected: %v", err)
	}
	parts := strings.Split(good, ".")

	rsaPubDER, _ := json.Marshal(rsaJWK) // any bytes derived from the public key
	derSig := func() string {
		input := encodeSegments(t, map[string]any{"alg": "ES256", "kid": "ec"}, validPayload())
		r, s, _ := ecdsa.Sign(rand.Reader, p256Key, digest(ES256.Hash(), []byte(input)))
		der, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		return input + "." + b64.EncodeToString(der)
	}()

	payloadWith := func(mut func(map[string]any)) map[string]any {
		p := validPayload()
		mut(p)
		return p
	}
	rs := func(p any) string {
		return forge(t, RS256, rsaKey, map[string]any{"alg": "RS256", "kid": "rsa"}, p)
	}

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", ErrMalformed},
		{"two segments", parts[0] + "." + parts[1], ErrMalformed},
		{"four segments", good + ".x", ErrMalformed},
		{"padding", good + "=", ErrMalformed},
		{"newline", parts[0] + "\n." + parts[1] + "." + parts[2], ErrMalformed},
		{"standard base64", strings.ReplaceAll(good, "-", "+"), ErrMalformed},
		{"empty signature", parts[0] + "." + parts[1] + ".", ErrMalformed},
		{"oversize", strings.Repeat("a", DefaultMaxTokenSize+1), ErrMalformed},
		{"alg none", encodeSegments(t, map[string]any{"alg": "none"}, validPayload()) + ".c2ln", ErrUnsupportedAlgorithm},
		{"alg missing", encodeSegments(t, map[string]any{"kid": "rsa"}, validPayload()) + ".c2ln", ErrMalformed},
		{"alg wrong case", encodeSegments(t, map[string]any{"alg": "rs256"}, validPayload()) + ".c2ln", ErrUnsupportedAlgorithm},
		{"header key case variant", encodeSegments(t, map[string]any{"ALG": "RS256", "alg": "none"}, validPayload()) + ".c2ln", ErrUnsupportedAlgorithm},
		{"duplicate header member", encodeSegments(t, `{"alg":"none","alg":"RS256","kid":"rsa"}`, validPayload()) + "." + parts[2], ErrMalformed},
		{"crit header", forge(t, RS256, rsaKey, map[string]any{"alg": "RS256", "kid": "rsa", "crit": []string{"exp"}}, validPayload()), ErrUnsupportedHeader},
		{"b64 header", forge(t, RS256, rsaKey, map[string]any{"alg": "RS256", "kid": "rsa", "b64": false}, validPayload()), ErrUnsupportedHeader},
		{"tampered payload", parts[0] + "." + b64.EncodeToString([]byte(`{"sub":"mallory"}`)) + "." + parts[2], ErrInvalidSignature},
		{"tampered signature", parts[0] + "." + parts[1] + "." + b64.EncodeToString(make([]byte, 256)), ErrInvalidSignature},
		{"HMAC with RSA public key (alg confusion)", forge(t, HS256, rsaPubDER, map[string]any{"alg": "HS256", "kid": "rsa"}, validPayload()), ErrNoMatchingKey},
		{"RSA token claiming ES256", forge(t, RS256, rsaKey, map[string]any{"alg": "ES256", "kid": "rsa"}, validPayload()), ErrNoMatchingKey},
		{"unknown kid", forge(t, RS256, rsaKey, map[string]any{"alg": "RS256", "kid": "other"}, validPayload()), ErrNoMatchingKey},
		{"ECDSA DER signature", derSig, ErrInvalidSignature},
		{"expired", rs(payloadWith(func(p map[string]any) { p["exp"] = testNow.Unix() })), ErrExpired},
		{"missing exp", rs(payloadWith(func(p map[string]any) { delete(p, "exp") })), ErrMissingClaim},
		{"exp as string", rs(payloadWith(func(p map[string]any) { p["exp"] = "4102444800" })), ErrMalformed},
		{"exp case variant", rs(payloadWith(func(p map[string]any) { delete(p, "exp"); p["EXP"] = 4102444800 })), ErrMissingClaim},
		{"duplicate exp", rs(`{"iss":"https://issuer.example","aud":"api","exp":1,"exp":4102444800}`), ErrMalformed},
		{"not yet valid", rs(payloadWith(func(p map[string]any) { p["nbf"] = testNow.Add(time.Minute).Unix() })), ErrNotYetValid},
		{"issued in future", rs(payloadWith(func(p map[string]any) { p["iat"] = testNow.Add(time.Minute).Unix() })), ErrIssuedInFuture},
		{"wrong issuer", rs(payloadWith(func(p map[string]any) { p["iss"] = "https://evil.example" })), ErrInvalidIssuer},
		{"missing issuer", rs(payloadWith(func(p map[string]any) { delete(p, "iss") })), ErrInvalidIssuer},
		{"wrong audience", rs(payloadWith(func(p map[string]any) { p["aud"] = []string{"other", "x"} })), ErrInvalidAudience},
		{"missing audience", rs(payloadWith(func(p map[string]any) { delete(p, "aud") })), ErrInvalidAudience},
		{"payload not an object", rs(`"hello"`), ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(ctx, tc.token)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if !errors.Is(err, ErrInvalidToken) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v does not wrap ErrInvalidToken", err)
			}
		})
	}
}

func TestAlgorithmAllowList(t *testing.T) {
	tok, s := mustSign(t, RS256, validClaims())
	v := newVerifier(t, NewStaticKeySet(s.VerificationKey()))
	v.algs = []Algorithm{ES256}
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v", err)
	}
}

func TestJWKAlgPinning(t *testing.T) {
	loadKeys(t)
	// The key is published for PS256 only; an RS256 signature by the same
	// key must not verify.
	jwk := JWK{KeyID: "k", Algorithm: PS256, Key: &rsaKey.PublicKey}
	v := newVerifier(t, NewStaticKeySet(jwk))
	tok := forge(t, RS256, rsaKey, map[string]any{"alg": "RS256", "kid": "k"}, validPayload())
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("err = %v", err)
	}
	jwk.Use = "enc"
	jwk.Algorithm = ""
	v = newVerifier(t, NewStaticKeySet(jwk))
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("use=enc: err = %v", err)
	}
}

func TestLeeway(t *testing.T) {
	c := validClaims()
	c.ExpiresAt = NewNumericDate(testNow.Add(-30 * time.Second))
	tok, s := mustSign(t, HS256, c)
	ks := NewStaticKeySet(s.VerificationKey())
	if _, err := newVerifier(t, ks).Verify(context.Background(), tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("no leeway: err = %v", err)
	}
	if _, err := newVerifier(t, ks, WithLeeway(time.Minute)).Verify(context.Background(), tok); err != nil {
		t.Fatalf("with leeway: err = %v", err)
	}
}

func TestExpectedType(t *testing.T) {
	tok, s := mustSign(t, HS256, validClaims(), WithType("at+jwt"))
	ks := NewStaticKeySet(s.VerificationKey())
	if _, err := newVerifier(t, ks, WithExpectedType("application/AT+JWT")).Verify(context.Background(), tok); err != nil {
		t.Fatalf("err = %v", err)
	}
	if _, err := newVerifier(t, ks, WithExpectedType("JWT")).Verify(context.Background(), tok); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewVerifierRequiresPolicy(t *testing.T) {
	ks := NewStaticKeySet()
	for name, opts := range map[string][]VerifierOption{
		"no algorithms": {WithAnyIssuer(), WithAnyAudience()},
		"no issuer":     {WithAlgorithms(RS256), WithAnyAudience()},
		"no audience":   {WithAlgorithms(RS256), WithAnyIssuer()},
		"unknown alg":   {WithAlgorithms("none"), WithAnyIssuer(), WithAnyAudience()},
		"negative skew": {WithAlgorithms(RS256), WithAnyIssuer(), WithAnyAudience(), WithLeeway(-time.Second)},
	} {
		if _, err := NewVerifier(ks, opts...); err == nil {
			t.Errorf("%s: NewVerifier succeeded", name)
		}
	}
}

func TestNewSignerRejectsBadKeys(t *testing.T) {
	loadKeys(t)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, tc := range map[string]struct {
		alg Algorithm
		key any
	}{
		"short HMAC":     {HS256, []byte("short")},
		"short RSA":      {RS256, small},
		"curve mismatch": {ES256, p384Key},
		"type mismatch":  {ES256, rsaKey},
		"public key":     {RS256, &rsaKey.PublicKey},
		"unknown alg":    {"none", hmacKey},
	} {
		if _, err := NewSigner(tc.alg, tc.key); err == nil {
			t.Errorf("%s: NewSigner succeeded", name)
		}
	}
}

func TestSignRejectsRegisteredClaimInExtra(t *testing.T) {
	s, _ := NewSigner(HS256, hmacKey)
	c := validClaims()
	c.Extra["sub"] = "mallory"
	if _, err := s.Sign(c); err == nil {
		t.Fatal("Sign succeeded with duplicate sub")
	}
}
