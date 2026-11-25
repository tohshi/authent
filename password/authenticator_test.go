package password

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

type fakeStore struct {
	creds   map[string]Credential
	updated map[string]string
	err     error
}

func (s *fakeStore) LookupCredential(_ context.Context, username string) (Credential, error) {
	if s.err != nil {
		return Credential{}, s.err
	}
	c, ok := s.creds[username]
	if !ok {
		return Credential{}, ErrUserNotFound
	}
	return c, nil
}

func (s *fakeStore) UpdateCredential(_ context.Context, subject, hash string) error {
	s.updated[subject] = hash
	return nil
}

func TestAuthenticate(t *testing.T) {
	h := newTestHasher(t)
	hash, _ := h.Hash("s3cret")
	store := &fakeStore{
		creds:   map[string]Credential{"alice": {Subject: "u-1", Hash: hash}},
		updated: map[string]string{},
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	a, err := NewAuthenticator(store, h, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	p, err := a.Authenticate(ctx, "alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate = %v", err)
	}
	if p.Subject != "u-1" || p.Method != authent.MethodPassword || !p.AuthTime.Equal(now) {
		t.Fatalf("unexpected principal %+v", p)
	}

	for _, tc := range []struct{ user, pw string }{
		{"alice", "wrong"},
		{"bob", "s3cret"},
		{"alice", ""},
	} {
		_, err := a.Authenticate(ctx, tc.user, tc.pw)
		if !errors.Is(err, ErrInvalidCredentials) || !errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("Authenticate(%q, %q) = %v, want ErrInvalidCredentials", tc.user, tc.pw, err)
		}
	}
	if len(store.updated) != 0 {
		t.Fatalf("unexpected rehash: %v", store.updated)
	}
}

func TestAuthenticateRehashesOutdatedHash(t *testing.T) {
	old, _ := NewHasher(Params{Memory: 32, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	hash, _ := old.Hash("s3cret")
	store := &fakeStore{
		creds:   map[string]Credential{"alice": {Subject: "u-1", Hash: hash}},
		updated: map[string]string{},
	}
	h := newTestHasher(t)
	a, _ := NewAuthenticator(store, h)
	if _, err := a.Authenticate(context.Background(), "alice", "s3cret"); err != nil {
		t.Fatal(err)
	}
	newHash, ok := store.updated["u-1"]
	if !ok {
		t.Fatal("hash was not upgraded")
	}
	if needs, _ := h.NeedsRehash(newHash); needs {
		t.Fatal("upgraded hash still needs rehash")
	}
	if err := h.Verify("s3cret", newHash); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticateRehashPreservesNFC(t *testing.T) {
	old, _ := NewHasher(Params{Memory: 32, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	policy, _ := NewPolicy(1, 64, &stubBreachChecker{})
	hash, err := policy.Hash(context.Background(), old, "cafe\u0301")
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{
		creds:   map[string]Credential{"alice": {Subject: "u-1", Hash: hash}},
		updated: map[string]string{},
	}
	h := newTestHasher(t)
	a, _ := NewAuthenticator(store, h)
	if _, err := a.Authenticate(context.Background(), "alice", "café"); err != nil {
		t.Fatal(err)
	}
	updated := store.updated["u-1"]
	if !strings.Contains(updated, ",norm=nfc$") {
		t.Fatalf("NFC tag lost during rehash: %q", updated)
	}
	if err := h.Verify("cafe\u0301", updated); err != nil {
		t.Fatalf("upgraded hash does not verify: %v", err)
	}
}

func TestAuthenticateStoreError(t *testing.T) {
	boom := errors.New("db down")
	a, _ := NewAuthenticator(&fakeStore{err: boom}, newTestHasher(t))
	_, err := a.Authenticate(context.Background(), "alice", "pw")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want store error", err)
	}
	if errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatal("store failure must not look like a credential failure")
	}
}

func TestAuthenticateMalformedStoredHash(t *testing.T) {
	store := &fakeStore{creds: map[string]Credential{"alice": {Subject: "u-1", Hash: "junk"}}}
	a, _ := NewAuthenticator(store, newTestHasher(t))
	_, err := a.Authenticate(context.Background(), "alice", "pw")
	if !errors.Is(err, ErrMalformedHash) || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrMalformedHash", err)
	}
}
