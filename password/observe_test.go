package password

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observetest"
)

func TestObserver(t *testing.T) {
	const secret = "pw-SECRET-7f3a"
	const typedIntoUsername = "user-SECRET-91c2"
	h := newTestHasher(t)
	hash, _ := h.Hash(secret)
	store := &fakeStore{creds: map[string]Credential{"alice": {Subject: "u-1", Hash: hash}}}
	rec := &observetest.Recorder{}
	a, err := NewAuthenticator(store, h, WithObserver(rec))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := a.Authenticate(ctx, "alice", secret); err != nil {
		t.Fatal(err)
	}
	_, wrong := a.Authenticate(ctx, "alice", "wrong")
	_, unknown := a.Authenticate(ctx, typedIntoUsername, secret)
	if wrong != ErrInvalidCredentials || unknown != ErrInvalidCredentials {
		t.Errorf("errors = %v, %v; want ErrInvalidCredentials for both", wrong, unknown)
	}
	store.err = errors.New("store down")
	if _, err := a.Authenticate(ctx, "alice", secret); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Errorf("store failure = %v", err)
	}

	ev := func(o authent.Outcome, r authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindAuthentication, Method: authent.MethodPassword, Outcome: o, Reason: r, Subject: sub}
	}
	rec.Expect(t, []authent.Event{
		ev(authent.OutcomeSuccess, "", "u-1"),
		ev(authent.OutcomeRejected, authent.ReasonInvalidCredentials, ""),
		ev(authent.OutcomeRejected, authent.ReasonUnknownUser, ""),
		ev(authent.OutcomeError, "", ""),
	}, secret, hash, typedIntoUsername)
}

func TestObserverCannotChangeTheResult(t *testing.T) {
	h := newTestHasher(t)
	hash, _ := h.Hash("s3cret")
	store := &fakeStore{creds: map[string]Credential{"alice": {Subject: "u-1", Hash: hash}}}

	newAuthenticator := func(o authent.Observer) *Authenticator {
		a, err := NewAuthenticator(store, h, WithObserver(o))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	t.Run("panicking observer", func(t *testing.T) {
		a := newAuthenticator(authent.ObserverFunc(func(context.Context, authent.Event) { panic("observer bug") }))
		if p, err := a.Authenticate(context.Background(), "alice", "s3cret"); err != nil || p.Subject != "u-1" {
			t.Errorf("success: %+v, %v", p, err)
		}
		if _, err := a.Authenticate(context.Background(), "alice", "wrong"); err != ErrInvalidCredentials {
			t.Errorf("rejection: %v", err)
		}
	})

	t.Run("observer blocking until the deadline runs after the store calls", func(t *testing.T) {
		a := newAuthenticator(authent.ObserverFunc(func(ctx context.Context, _ authent.Event) { <-ctx.Done() }))
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if p, err := a.Authenticate(ctx, "alice", "s3cret"); err != nil || p.Subject != "u-1" {
			t.Errorf("%+v, %v", p, err)
		}
	})
}
