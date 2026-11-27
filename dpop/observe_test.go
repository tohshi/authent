package dpop

import (
	"context"
	"testing"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observetest"
	"github.com/tohshi/authent/jwt"
)

func TestObserver(t *testing.T) {
	ctx := context.Background()
	signer, keys := newTokenIssuer(t)
	rec := &observetest.Recorder{}
	a, err := NewAuthenticator(newTokenVerifier(t, keys, jwt.WithConfirmationClaim()), newVerifier(t), WithObserver(rec))
	if err != nil {
		t.Fatal(err)
	}
	p := newProver(t)
	bound := accessTokenFor(t, signer, map[string]any{"jkt": p.Thumbprint()})
	var proofs []string
	request := func(prover *Prover, tok string) Request {
		proof, err := prover.Proof("GET", resourceURL, tok)
		if err != nil {
			t.Fatal(err)
		}
		proofs = append(proofs, proof)
		return Request{Method: "GET", URL: resourceURL, Proofs: []string{proof}, AccessToken: tok}
	}

	ok := request(p, bound)
	_, _ = a.Authenticate(ctx, ok)
	_, _ = a.Authenticate(ctx, ok)
	_, _ = a.Authenticate(ctx, request(newProver(t), bound))
	_, _ = a.Authenticate(ctx, Request{Method: "GET", URL: resourceURL})
	_, _ = a.Authenticate(ctx, request(p, bound[:len(bound)-4]+"AAAA"))
	bad := request(p, bound)
	bad.Proofs[0] = bad.Proofs[0][:len(bad.Proofs[0])-4] + "AAAA"
	_, _ = a.Authenticate(ctx, bad)

	ev := func(o authent.Outcome, r authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindAuthentication, Method: authent.MethodDPoP, Outcome: o, Reason: r, Subject: sub}
	}
	rec.Expect(t, []authent.Event{
		ev(authent.OutcomeSuccess, "", "user-1"),
		ev(authent.OutcomeRejected, authent.ReasonReplayed, ""),
		ev(authent.OutcomeRejected, authent.ReasonKeyMismatch, ""),
		ev(authent.OutcomeRejected, authent.ReasonNoCredentials, ""),
		ev(authent.OutcomeRejected, authent.ReasonBadSignature, ""),
		ev(authent.OutcomeRejected, authent.ReasonInvalidProof, ""),
	}, append(proofs, bound, AccessTokenHash(bound), p.Thumbprint())...)
}
