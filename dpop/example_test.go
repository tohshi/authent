package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/dpop"
	"github.com/tohshi/authent/jwt"
)

// A resource server accepts a DPoP-bound access token only together with a
// proof signed by the key the token is bound to.
func Example() {
	ctx := context.Background()

	// The client's key pair. The authorization server binds the access
	// token to its thumbprint with the "cnf" claim.
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prover, _ := dpop.NewProver(jwt.ES256, clientKey)

	asKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	as, _ := jwt.NewSigner(jwt.ES256, asKey, jwt.WithType("at+jwt"))
	accessToken, _ := as.Sign(jwt.Claims{
		Issuer:    "https://as.example.com",
		Subject:   "u1",
		Audience:  jwt.Audience{"api"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		Extra:     map[string]any{"cnf": map[string]any{"jkt": prover.Thumbprint()}},
	})

	// The resource server.
	tokens, _ := jwt.NewVerifier(jwt.NewStaticKeySet(as.VerificationKey()),
		jwt.WithAlgorithms(jwt.ES256),
		jwt.WithIssuer("https://as.example.com"),
		jwt.WithAudience("api"),
		jwt.WithExpectedType("at+jwt"),
		jwt.WithConfirmationClaim(),
	)
	proofs, _ := dpop.NewVerifier(dpop.WithAlgorithms(jwt.ES256), dpop.WithReplayCache(jwt.NewMemoryReplayCache()))
	auth, _ := dpop.NewAuthenticator(tokens, proofs)

	// The client sends "Authorization: DPoP <token>" and a fresh proof.
	const uri = "https://api.example.com/v1/items"
	proof, _ := prover.Proof("GET", uri, accessToken)
	req := dpop.Request{Method: "GET", URL: uri, Proofs: []string{proof}, AccessToken: accessToken}

	p, err := auth.Authenticate(ctx, req)
	fmt.Println(p.Subject, p.Method, err)

	// Replaying the same proof fails.
	_, err = auth.Authenticate(ctx, req)
	fmt.Println(errors.Is(err, dpop.ErrReplayed), errors.Is(err, authent.ErrUnauthenticated))
	fmt.Println(proofs.Challenge(err))
	// Output:
	// u1 dpop <nil>
	// true true
	// DPoP error="invalid_dpop_proof", algs="ES256"
}
