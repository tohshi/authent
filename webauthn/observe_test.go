package webauthn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observetest"
)

func TestObserver(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	rec := &observetest.Recorder{}
	rp, err := New(Config{RPID: "example.org", Origins: []string{"https://example.org"}}, store,
		WithClock(func() time.Time { return testNow }), WithObserver(rec))
	if err != nil {
		t.Fatal(err)
	}
	a := newSoftAuthenticator(t)
	cred := register(t, rp, store, a)
	var responses []string
	login := func(a *softAuthenticator) {
		_, ch, err := rp.BeginLogin([]Credential{cred})
		if err != nil {
			t.Fatal(err)
		}
		resp := a.get(ch)
		responses = append(responses, string(resp), b64.EncodeToString(ch.Value))
		_, _ = rp.FinishLogin(ctx, ch, resp)
	}

	a.signCount = 5
	login(a)
	login(a)
	a.signCount = 6
	a.origin = "https://evil.example"
	login(a)
	a.origin = "https://example.org"
	a.corruptSig = true
	login(a)
	a.corruptSig = false
	login(newSoftAuthenticator(t))
	store.lookupErr = errors.New("db down")
	login(a)

	ev := func(o authent.Outcome, r authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindAuthentication, Method: authent.MethodWebAuthn, Outcome: o, Reason: r, Subject: sub}
	}
	rec.Expect(t, []authent.Event{
		ev(authent.OutcomeSuccess, "", "u-1"),
		ev(authent.OutcomeRejected, authent.ReasonSignCount, ""),
		ev(authent.OutcomeRejected, authent.ReasonWrongOrigin, ""),
		ev(authent.OutcomeRejected, authent.ReasonBadSignature, ""),
		ev(authent.OutcomeRejected, authent.ReasonInvalidCredentials, ""),
		ev(authent.OutcomeError, "", ""),
	}, append(responses, b64.EncodeToString(cred.ID), string(testUser.Handle))...)
}
