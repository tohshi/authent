package jwt

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type jwksServer struct {
	*httptest.Server
	mu           sync.Mutex
	set          JWKSet
	fail         bool
	hits         atomic.Int32
	delay        time.Duration
	cacheControl []string
}

func newJWKSServer(t *testing.T, keys ...JWK) *jwksServer {
	s := &jwksServer{set: JWKSet{Keys: keys}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		time.Sleep(s.delay)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		for _, v := range s.cacheControl {
			w.Header().Add("Cache-Control", v)
		}
		_ = json.MarshalWrite(w, s.set)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) setKeys(keys ...JWK) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set = JWKSet{Keys: keys}
}

func (s *jwksServer) setFail(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = fail
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func ecSigner(t *testing.T, kid string) *Signer {
	t.Helper()
	loadKeys(t)
	s, err := NewSigner(ES256, p256Key, WithKeyID(kid))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newRemote(t *testing.T, srv *jwksServer, clock *fakeClock) *RemoteKeySet {
	t.Helper()
	ks, err := NewRemoteKeySet(srv.URL, WithHTTPClient(srv.Client()), WithKeySetClock(clock.now),
		WithRefreshInterval(time.Hour), WithMinRefreshInterval(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestRemoteKeySetCachesAndRotates(t *testing.T) {
	ctx := context.Background()
	s1 := ecSigner(t, "k1")
	srv := newJWKSServer(t, s1.VerificationKey())
	clock := &fakeClock{t: testNow}
	ks := newRemote(t, srv, clock)

	keys, err := ks.VerificationKeys(ctx, "k1")
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys = %v, %v", keys, err)
	}
	_, _ = ks.VerificationKeys(ctx, "k1")
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("fetched %d times, want 1 (cached)", got)
	}

	// The issuer rotates to k2. An unknown kid within the minimum refresh
	// interval does not trigger a fetch.
	s2, _ := NewSigner(EdDSA, edKey, WithKeyID("k2"))
	srv.setKeys(s1.VerificationKey(), s2.VerificationKey())
	if keys, _ := ks.VerificationKeys(ctx, "k2"); len(keys) != 0 || srv.hits.Load() != 1 {
		t.Fatalf("throttled lookup fetched or matched: %v", keys)
	}
	clock.advance(2 * time.Minute)
	if keys, _ := ks.VerificationKeys(ctx, "k2"); len(keys) != 1 || srv.hits.Load() != 2 {
		t.Fatalf("rotation not picked up: %v, hits %d", keys, srv.hits.Load())
	}

	// After the refresh interval the set is refetched even for known kids.
	clock.advance(2 * time.Hour)
	_, _ = ks.VerificationKeys(ctx, "k1")
	if got := srv.hits.Load(); got != 3 {
		t.Fatalf("fetched %d times, want 3", got)
	}
}

func TestRemoteKeySetServesStaleKeysOnFailure(t *testing.T) {
	ctx := context.Background()
	s1 := ecSigner(t, "k1")
	srv := newJWKSServer(t, s1.VerificationKey())
	clock := &fakeClock{t: testNow}
	ks := newRemote(t, srv, clock)
	if _, err := ks.VerificationKeys(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	srv.setFail(true)
	clock.advance(2 * time.Hour)
	keys, err := ks.VerificationKeys(ctx, "k1")
	if err != nil || len(keys) != 1 {
		t.Fatalf("stale keys not served: %v, %v", keys, err)
	}
}

func TestRemoteKeySetThrottlesFailures(t *testing.T) {
	ctx := context.Background()
	srv := newJWKSServer(t)
	srv.setFail(true)
	clock := &fakeClock{t: testNow}
	ks := newRemote(t, srv, clock)
	for range 5 {
		if _, err := ks.VerificationKeys(ctx, "k1"); err == nil {
			t.Fatal("expected error")
		}
	}
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("fetched %d times, want 1", got)
	}
}

func TestRemoteKeySetDeduplicatesConcurrentFetches(t *testing.T) {
	s1 := ecSigner(t, "k1")
	srv := newJWKSServer(t, s1.VerificationKey())
	srv.delay = 50 * time.Millisecond
	ks := newRemote(t, srv, &fakeClock{t: testNow})
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := ks.VerificationKeys(context.Background(), "k1"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("fetched %d times, want 1", got)
	}
}

func TestRemoteKeySetEndToEnd(t *testing.T) {
	s1 := ecSigner(t, "k1")
	srv := newJWKSServer(t, s1.VerificationKey())
	ks := newRemote(t, srv, &fakeClock{t: testNow})
	v := newVerifier(t, ks)
	tok, err := s1.Sign(validClaims())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteKeySetHonorsCacheControl(t *testing.T) {
	for name, tc := range map[string]struct {
		header []string
		fresh  time.Duration
	}{
		"absent":                {nil, time.Hour},
		"max-age":               {[]string{"max-age=600"}, 10 * time.Minute},
		"with other directives": {[]string{"public, max-age=7200, must-revalidate"}, 2 * time.Hour},
		"case-insensitive":      {[]string{"Max-Age=600"}, 10 * time.Minute},
		"below minimum":         {[]string{"max-age=5"}, time.Minute},
		"above maximum":         {[]string{"max-age=86400"}, 6 * time.Hour},
		"beyond 2^31":           {[]string{"max-age=99999999999999999999"}, 6 * time.Hour},
		"no-store":              {[]string{"no-store"}, time.Minute},
		"no-cache wins":         {[]string{"max-age=600", "no-cache"}, time.Minute},
		"invalid max-age":       {[]string{"max-age=ten"}, time.Minute},
		"quoted max-age":        {[]string{`max-age="600"`}, time.Minute},
		"repeated max-age":      {[]string{"max-age=600, max-age=7200"}, time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			srv := newJWKSServer(t, ecSigner(t, "k1").VerificationKey())
			srv.cacheControl = tc.header
			clock := &fakeClock{t: testNow}
			ks, err := NewRemoteKeySet(srv.URL, WithHTTPClient(srv.Client()), WithKeySetClock(clock.now),
				WithRefreshInterval(time.Hour), WithMinRefreshInterval(time.Minute), WithMaxRefreshInterval(6*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ks.VerificationKeys(ctx, "k1"); err != nil {
				t.Fatal(err)
			}
			clock.advance(tc.fresh - time.Second)
			_, _ = ks.VerificationKeys(ctx, "k1")
			if got := srv.hits.Load(); got != 1 {
				t.Fatalf("refetched %v after the first fetch, before the set went stale", tc.fresh-time.Second)
			}
			clock.advance(time.Second)
			_, _ = ks.VerificationKeys(ctx, "k1")
			if got := srv.hits.Load(); got != 2 {
				t.Fatalf("not refetched %v after the first fetch", tc.fresh)
			}
		})
	}
}

func FuzzCacheLifetime(f *testing.F) {
	for _, s := range []string{"max-age=600", "no-store", "public, max-age=99999999999999999999", "max-age=", ",,=,"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		d, ok := cacheLifetime([]string{header})
		if d < 0 || d > (1<<31)*time.Second || (!ok && d != 0) {
			t.Fatalf("cacheLifetime(%q) = %v, %v", header, d, ok)
		}
	})
}

func TestNewRemoteKeySetRejectsInvertedIntervals(t *testing.T) {
	_, err := NewRemoteKeySet("https://issuer.example/jwks",
		WithMinRefreshInterval(time.Hour), WithMaxRefreshInterval(time.Minute))
	if err == nil {
		t.Fatal("minimum refresh interval above the maximum accepted")
	}
}

func TestNewRemoteKeySetRequiresHTTPS(t *testing.T) {
	for _, u := range []string{"http://example.com/jwks", "/jwks", "https://", "::"} {
		if _, err := NewRemoteKeySet(u); err == nil {
			t.Errorf("NewRemoteKeySet(%q) succeeded", u)
		}
	}
}

func TestParseJWK(t *testing.T) {
	loadKeys(t)
	ok := []JWK{
		{KeyID: "r", Key: &rsaKey.PublicKey, Use: "sig"},
		{KeyID: "e", Algorithm: ES384, Key: &p384Key.PublicKey},
		{KeyID: "e5", Key: &p521Key.PublicKey},
		{KeyID: "o", Key: edKey.Public()},
	}
	for _, k := range ok {
		b, err := json.Marshal(k)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseJWK(b)
		if err != nil {
			t.Fatalf("ParseJWK(%s) = %v", b, err)
		}
		if got.KeyID != k.KeyID || got.Algorithm != k.Algorithm || got.Use != k.Use {
			t.Fatalf("round trip mismatch: %+v vs %+v", got, k)
		}
	}

	ecGood, _ := json.Marshal(JWK{Key: &p256Key.PublicKey})
	var ec map[string]any
	_ = json.Unmarshal(ecGood, &ec)
	offCurve := map[string]any{"kty": "EC", "crv": "P-256", "x": ec["x"], "y": ec["x"]}
	offCurveJSON, _ := json.Marshal(offCurve)

	bad := map[string]string{
		"private RSA": `{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}`,
		"symmetric":   `{"kty":"oct","k":"c2VjcmV0"}`,
		"short RSA":   `{"kty":"RSA","n":"` + b64.EncodeToString(make([]byte, 128)) + `","e":"AQAB"}`,
		"off curve":   string(offCurveJSON),
		"bad crv":     `{"kty":"EC","crv":"P-192","x":"AA","y":"AA"}`,
		"short x":     `{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`,
		"alg mismatch": func() string {
			b, _ := json.Marshal(JWK{Algorithm: ES256, Key: edKey.Public()})
			return string(b)
		}(),
		"HS alg on RSA": `{"kty":"RSA","alg":"HS256","n":"` + b64.EncodeToString(rsaKey.N.Bytes()) + `","e":"AQAB"}`,
		"dup member":    `{"kty":"OKP","kty":"RSA","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
	}
	for name, in := range bad {
		if _, err := ParseJWK([]byte(in)); err == nil {
			t.Errorf("%s: ParseJWK succeeded", name)
		}
	}
}

func TestParseJWKSetSkipsUnusableKeys(t *testing.T) {
	in := `{"keys":[
		{"kty":"oct","k":"c2VjcmV0"},
		{"kty":"RSA","use":"enc","alg":"RSA-OAEP","n":"AQAB","e":"AQAB"},
		{"kty":"OKP","crv":"X25519","x":"AAAA"},
		{"kty":"OKP","crv":"Ed25519","kid":"ok","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	]}`
	set, err := ParseJWKSet([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "ok" {
		t.Fatalf("keys = %+v", set.Keys)
	}
	if _, err := ParseJWKSet([]byte(`{"keys":`)); err == nil {
		t.Fatal("truncated set accepted")
	}
}

func TestHMACKeyNotMarshaled(t *testing.T) {
	k, err := NewHMACKey("h", HS256, hmacKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(k); err == nil {
		t.Fatal("HMAC secret was marshaled")
	}
	if _, err := NewHMACKey("h", HS256, []byte("short")); err == nil {
		t.Fatal("short HMAC key accepted")
	}
	if _, err := NewHMACKey("h", RS256, hmacKey); err == nil {
		t.Fatal("non-HMAC alg accepted")
	}
}

func FuzzVerify(f *testing.F) {
	loadKeys(f)
	s, _ := NewSigner(ES256, p256Key, WithKeyID("k"))
	tok, _ := s.Sign(validClaims())
	f.Add(tok)
	// Ed25519 signatures are deterministic, so every fuzz worker process
	// computes the same seed.
	embedded, _ := NewSigner(EdDSA, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), WithJWKHeader())
	selfSigned, _ := embedded.SignPayload([]byte(`{"jti":"x"}`))
	f.Add(selfSigned)
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add("a.b.c")
	v, err := NewVerifier(NewStaticKeySet(s.VerificationKey()), WithAlgorithms(allAlgs...),
		WithIssuer(testIssuer), WithAudience("api"), WithClock(testClock))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, token string) {
		c, err := v.Verify(context.Background(), token)
		if err == nil {
			// Anything accepted must carry a valid signature by our key,
			// which the fuzzer cannot forge; only the seed should pass.
			if token != tok {
				t.Fatalf("accepted unexpected token %q (%+v)", token, c)
			}
			return
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("error %v does not wrap ErrInvalidToken", err)
		}

		// The same holds for tokens verified with their embedded key: the
		// fuzzer cannot produce a new valid signature for any key.
		if _, err := VerifyWithEmbeddedKey(token, ES256, RS256, EdDSA); err == nil {
			if token != selfSigned {
				t.Fatalf("accepted unexpected self-signed token %q", token)
			}
		} else if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("error %v does not wrap ErrInvalidToken", err)
		}
	})
}
