package apikey

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observetest"
)

func TestObserver(t *testing.T) {
	now := t0
	store := &countingStore{MemoryStore: NewMemoryStore()}
	rec := &observetest.Recorder{}
	m, err := NewManager("test", store, WithClock(func() time.Time { return now }), WithObserver(rec))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	key, r, err := m.Create(ctx, "u1", t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	id, secret, _ := parse("test", key)
	wrong := append([]byte(nil), secret...)
	wrong[0] ^= 1

	_, _ = m.Authenticate(ctx, key)
	_, _ = m.Authenticate(ctx, format("test", id, wrong))
	_, _ = m.Authenticate(ctx, key+"x")
	now = t0.Add(time.Hour)
	_, _ = m.Authenticate(ctx, key)
	now = t0
	if err := m.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	_, _ = m.Authenticate(ctx, key)
	store.err = errors.New("db down")
	_, _ = m.Authenticate(ctx, key)

	ev := func(o authent.Outcome, reason authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindAuthentication, Method: authent.MethodAPIKey, Outcome: o, Reason: reason, Subject: sub}
	}
	rec.Expect(t, []authent.Event{
		ev(authent.OutcomeSuccess, "", "u1"),
		ev(authent.OutcomeRejected, authent.ReasonInvalidCredentials, ""),
		ev(authent.OutcomeRejected, authent.ReasonMalformed, ""),
		ev(authent.OutcomeRejected, authent.ReasonExpired, ""),
		ev(authent.OutcomeRejected, authent.ReasonRevoked, ""),
		ev(authent.OutcomeError, "", ""),
	}, key, b32.EncodeToString(secret), hex.EncodeToString(r.SecretHash[:]), string(r.SecretHash[:]))
}
