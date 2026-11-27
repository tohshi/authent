package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observetest"
)

func TestObserver(t *testing.T) {
	ctx := context.Background()
	s := ecSigner(t, "k")
	keys := NewStaticKeySet(s.VerificationKey())
	rec := &observetest.Recorder{}
	v := newVerifier(t, keys, WithObserver(rec), WithReplayCache(NewMemoryReplayCache()))
	sign := func(c Claims) string {
		tok, err := s.Sign(c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	var tokens []string
	run := func(f func(context.Context, string) error, c Claims) {
		tok := sign(c)
		tokens = append(tokens, tok)
		_ = f(ctx, tok)
	}
	verify := func(ctx context.Context, tok string) error { _, err := v.Verify(ctx, tok); return err }
	authenticate := func(ctx context.Context, tok string) error { _, err := v.Authenticate(ctx, tok); return err }

	run(authenticate, claimsWithID("1"))
	run(verify, claimsWithID("2"))
	_ = verify(ctx, tokens[1])
	expired := claimsWithID("3")
	expired.ExpiresAt = NewNumericDate(testNow.Add(-time.Hour))
	run(verify, expired)
	wrongAud := claimsWithID("4")
	wrongAud.Audience = Audience{"other"}
	run(verify, wrongAud)
	noSub := claimsWithID("5")
	noSub.Subject = ""
	run(authenticate, noSub)
	tampered := tokens[0][:len(tokens[0])-4] + "AAAA"
	_ = verify(ctx, tampered)

	failing := newVerifier(t, keys, WithObserver(rec), WithReplayCache(failingReplayCache{}))
	_, _ = failing.Verify(ctx, sign(claimsWithID("6")))

	auth := func(o authent.Outcome, r authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindAuthentication, Method: authent.MethodJWT, Outcome: o, Reason: r, Subject: sub}
	}
	tv := func(o authent.Outcome, r authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindTokenVerification, Method: authent.MethodJWT, Outcome: o, Reason: r, Subject: sub}
	}
	secrets := append(tokens, tampered)
	for _, tok := range tokens {
		secrets = append(secrets, tok[len(tok)-20:])
	}
	rec.Expect(t, []authent.Event{
		auth(authent.OutcomeSuccess, "", "alice"),
		tv(authent.OutcomeSuccess, "", "alice"),
		tv(authent.OutcomeRejected, authent.ReasonReplayed, ""),
		tv(authent.OutcomeRejected, authent.ReasonExpired, ""),
		tv(authent.OutcomeRejected, authent.ReasonWrongAudience, ""),
		auth(authent.OutcomeRejected, authent.ReasonMissingClaim, ""),
		tv(authent.OutcomeRejected, authent.ReasonBadSignature, ""),
		tv(authent.OutcomeError, "", ""),
	}, secrets...)
}
