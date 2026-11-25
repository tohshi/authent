package dpop

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

const issuer = "https://as.example.com"

func newTokenIssuer(t *testing.T) (*jwt.Signer, jwt.KeySet) {
	t.Helper()
	s, err := jwt.NewSigner(jwt.ES256, newKey(t), jwt.WithType("at+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	return s, jwt.NewStaticKeySet(s.VerificationKey())
}

func accessTokenFor(t *testing.T, s *jwt.Signer, cnf any) string {
	t.Helper()
	c := jwt.Claims{
		Issuer:    issuer,
		Subject:   "user-1",
		Audience:  jwt.Audience{"api"},
		ExpiresAt: jwt.NewNumericDate(testNow.Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(testNow),
		Extra:     map[string]any{},
	}
	if cnf != nil {
		c.Extra["cnf"] = cnf
	}
	tok, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newTokenVerifier(t *testing.T, keys jwt.KeySet, opts ...jwt.VerifierOption) *jwt.Verifier {
	t.Helper()
	base := []jwt.VerifierOption{
		jwt.WithAlgorithms(jwt.ES256), jwt.WithIssuer(issuer), jwt.WithAudience("api"),
		jwt.WithExpectedType("at+jwt"), jwt.WithClock(func() time.Time { return testNow }),
	}
	v, err := jwt.NewVerifier(keys, append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAuthenticator(t *testing.T) {
	ctx := context.Background()
	signer, keys := newTokenIssuer(t)
	a, err := NewAuthenticator(newTokenVerifier(t, keys, jwt.WithConfirmationClaim()), newVerifier(t))
	if err != nil {
		t.Fatal(err)
	}
	p := newProver(t)
	bound := accessTokenFor(t, signer, map[string]any{"jkt": p.Thumbprint()})
	request := func(prover *Prover, tok string) Request {
		proof, err := prover.Proof("GET", resourceURL, tok)
		if err != nil {
			t.Fatal(err)
		}
		return Request{Method: "GET", URL: resourceURL, Proofs: []string{proof}, AccessToken: tok}
	}

	principal, err := a.Authenticate(ctx, request(p, bound))
	if err != nil {
		t.Fatalf("Authenticate = %v", err)
	}
	if principal.Subject != "user-1" || principal.Method != authent.MethodDPoP || principal.Issuer != issuer {
		t.Fatalf("principal = %+v", principal)
	}

	for name, tc := range map[string]struct {
		r    Request
		want error
	}{
		"stolen token, attacker's key": {request(newProver(t), bound), ErrKeyBinding},
		"unbound token":                {request(p, accessTokenFor(t, signer, nil)), ErrKeyBinding},
		"cnf without jkt":              {request(p, accessTokenFor(t, signer, map[string]any{"x5t#S256": "abc"})), ErrKeyBinding},
		"no token":                     {Request{Method: "GET", URL: resourceURL}, ErrNoToken},
		"forged token":                 {request(p, bound+"x"), jwt.ErrInvalidToken},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := a.Authenticate(ctx, tc.r)
			if !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	// RFC 9449 §7.2: the same token must not work as a bearer token.
	if _, err := newTokenVerifier(t, keys).Authenticate(ctx, bound); !errors.Is(err, jwt.ErrSenderConstrained) {
		t.Fatalf("bound token accepted as bearer: err = %v", err)
	}
}

// fakeServer is an authorization server token endpoint and a resource
// server that both require DPoP nonces.
type fakeServer struct {
	*httptest.Server
	proofs *Verifier

	mu       sync.Mutex
	nonce    string
	requests int
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	s := &fakeServer{nonce: "nonce-1"}
	s.proofs = newVerifier(t, WithNonce(func(_ context.Context, n string) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return n == s.nonce
	}))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		s.count()
		body, _ := io.ReadAll(r.Body)
		switch string(body) {
		case "grant_type=refresh_token":
		case "grant_type=bad":
			s.reject(w, http.StatusBadRequest, errors.New("invalid_grant"))
			return
		default:
			http.Error(w, "body lost on retry", http.StatusTeapot)
			return
		}
		if _, err := s.check(r, ""); err != nil {
			s.reject(w, http.StatusBadRequest, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP"}`))
	})
	mux.HandleFunc("GET /resource", func(w http.ResponseWriter, r *http.Request) {
		s.count()
		tok, err := AccessToken(r.Header.Get("Authorization"))
		if err == nil {
			_, err = s.check(r, tok)
		}
		if err != nil {
			s.reject(w, http.StatusUnauthorized, err)
			return
		}
		s.mu.Lock()
		s.nonce = "nonce-2" // rotate with a successful response
		w.Header().Set(NonceHeaderName, s.nonce)
		s.mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	})
	s.Server = httptest.NewTLSServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *fakeServer) count() {
	s.mu.Lock()
	s.requests++
	s.mu.Unlock()
}

func (s *fakeServer) check(r *http.Request, tok string) (*Proof, error) {
	return s.proofs.Verify(r.Context(), Request{
		Method: r.Method, URL: s.URL + r.URL.RequestURI(), Proofs: r.Header.Values(HeaderName), AccessToken: tok,
	})
}

func (s *fakeServer) reject(w http.ResponseWriter, status int, err error) {
	s.mu.Lock()
	w.Header().Set(NonceHeaderName, s.nonce)
	s.mu.Unlock()
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", s.proofs.Challenge(err))
		w.WriteHeader(status)
		return
	}
	code := "invalid_grant"
	switch {
	case errors.Is(err, ErrUseNonce):
		code = "use_dpop_nonce"
	case errors.Is(err, ErrInvalidProof):
		code = "invalid_dpop_proof"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}

func TestTransportNonceRetry(t *testing.T) {
	s := newFakeServer(t)
	p := newProver(t)
	client := &http.Client{Transport: &Transport{Prover: p, Base: s.Client().Transport}}

	// Token endpoint: 400 use_dpop_nonce, then a retry with the same body.
	resp, err := client.Post(s.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader("grant_type=refresh_token"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || s.requests != 2 {
		t.Fatalf("token: status %d, %d requests, body %s", resp.StatusCode, s.requests, body)
	}

	// The resource is on the same origin, so the nonce learned at the
	// token endpoint is reused and no retry is needed.
	rs := &http.Client{Transport: &Transport{
		Prover: p,
		Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "at", TokenType: "DPoP"}),
		Base:   s.Client().Transport,
	}}
	resp, err = rs.Get(s.URL + "/resource")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || s.requests != 3 {
		t.Fatalf("resource: status %d, %d requests", resp.StatusCode, s.requests)
	}
	// The nonce rotated in the 200 response is used next time.
	if p.nonce(s.URL) != "nonce-2" {
		t.Fatalf("nonce = %q", p.nonce(s.URL))
	}
	resp, err = rs.Get(s.URL + "/resource")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || s.requests != 4 {
		t.Fatalf("rotated nonce: status %d, %d requests", resp.StatusCode, s.requests)
	}

	// A fresh Prover has no nonce: 401 with a use_dpop_nonce challenge,
	// then a retry.
	rs.Transport.(*Transport).Prover = newProver(t)
	resp, err = rs.Get(s.URL + "/resource")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || s.requests != 6 {
		t.Fatalf("401 retry: status %d, %d requests", resp.StatusCode, s.requests)
	}
}

func TestTransportDoesNotRetryOtherErrors(t *testing.T) {
	s := newFakeServer(t)
	// A 400 with a DPoP-Nonce header but another error is not retried: an
	// authorization code must not be sent twice for nothing.
	p := newProver(t)
	client := &http.Client{Transport: &Transport{Prover: p, Base: s.Client().Transport}}
	resp, err := client.Post(s.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader("grant_type=bad"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "invalid_grant") || s.requests != 1 {
		t.Fatalf("status %d, body %s, %d requests", resp.StatusCode, body, s.requests)
	}

	// A body that cannot be replayed is sent once and the response is
	// returned as is, with its body intact.
	p = newProver(t)
	client = &http.Client{Transport: &Transport{Prover: p, Base: s.Client().Transport}}
	req, _ := http.NewRequest("POST", s.URL+"/token", io.NopCloser(strings.NewReader("grant_type=refresh_token")))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "use_dpop_nonce") || s.requests != 2 {
		t.Fatalf("status %d, body %s, %d requests", resp.StatusCode, body, s.requests)
	}
}

func TestTransportRefusesBearerTokens(t *testing.T) {
	s := newFakeServer(t)
	client := &http.Client{Transport: &Transport{
		Prover: newProver(t),
		Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "at", TokenType: "Bearer"}),
		Base:   s.Client().Transport,
	}}
	if _, err := client.Get(s.URL + "/resource"); err == nil {
		t.Fatal("Bearer token sent")
	}
	if s.requests != 0 {
		t.Fatal("request reached the server")
	}
}
