package session

import (
	"context"
	"errors"
	"testing"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observetest"
)

func TestObserver(t *testing.T) {
	rec := &observetest.Recorder{}
	m, _, _ := setup(t, WithObserver(rec))
	ctx := context.Background()
	token, s, err := m.Create(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := newToken()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.Get(ctx, token); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{token + "x", unknown} {
		if _, err := m.Get(ctx, tok); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("Get = %v", err)
		}
	}
	failing, err := NewManager(failingStore{errors.New("redis down")}, WithObserver(rec))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Get(ctx, token); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("store failure: %v", err)
	}

	ev := func(o authent.Outcome, r authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindAuthentication, Method: authent.MethodSession, Outcome: o, Reason: r, Subject: sub}
	}
	rec.Expect(t, []authent.Event{
		ev(authent.OutcomeSuccess, "", "alice"),
		ev(authent.OutcomeRejected, authent.ReasonMalformed, ""),
		ev(authent.OutcomeRejected, authent.ReasonInvalidCredentials, ""),
		ev(authent.OutcomeError, "", ""),
	}, token, unknown, s.Handle(), s.CSRFToken())
}
