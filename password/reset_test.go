package password

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

type spyResetStore struct {
	*MemoryResetStore
	puts    []ResetToken
	takes   int
	takeErr error
}

func (s *spyResetStore) PutResetToken(ctx context.Context, t ResetToken) error {
	s.puts = append(s.puts, t)
	return s.MemoryResetStore.PutResetToken(ctx, t)
}

func (s *spyResetStore) TakeResetToken(ctx context.Context, hash [sha256.Size]byte) (ResetToken, error) {
	s.takes++
	if s.takeErr != nil {
		return ResetToken{}, s.takeErr
	}
	return s.MemoryResetStore.TakeResetToken(ctx, hash)
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newResetManager(t *testing.T, store ResetTokenStore, clock *fakeClock) *ResetManager {
	t.Helper()
	m, err := NewResetManager(store, WithResetTTL(time.Hour), WithResetClock(clock.now))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func wantInvalidResetToken(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidResetToken) || !errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrInvalidResetToken", err)
	}
}

func TestResetTokenSingleUse(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	store := &spyResetStore{MemoryResetStore: NewMemoryResetStore()}
	m := newResetManager(t, store, clock)

	token, err := m.Issue(ctx, "u-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) < 32 {
		t.Fatalf("token %q does not carry 256 bits", token)
	}
	if len(store.puts) != 1 {
		t.Fatalf("store received %d tokens", len(store.puts))
	}
	stored := store.puts[0]
	if stored.Hash != sha256.Sum256(raw) || stored.Subject != "u-1" || !stored.ExpiresAt.Equal(clock.t.Add(time.Hour)) {
		t.Fatalf("stored %+v, want the SHA-256 of the token, the subject and the expiry", stored)
	}

	subject, err := m.Redeem(ctx, token)
	if err != nil || subject != "u-1" {
		t.Fatalf("Redeem = %q, %v", subject, err)
	}
	_, err = m.Redeem(ctx, token)
	wantInvalidResetToken(t, err)
}

func TestResetTokenExpires(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	m := newResetManager(t, NewMemoryResetStore(), clock)

	fresh, _ := m.Issue(ctx, "u-1")
	expiring, _ := m.Issue(ctx, "u-2")
	clock.t = clock.t.Add(time.Hour - time.Nanosecond)
	if _, err := m.Redeem(ctx, fresh); err != nil {
		t.Fatalf("token rejected before its expiry: %v", err)
	}
	clock.t = clock.t.Add(time.Nanosecond)
	_, err := m.Redeem(ctx, expiring)
	wantInvalidResetToken(t, err)

	clock.t = clock.t.Add(-time.Hour)
	_, err = m.Redeem(ctx, expiring)
	wantInvalidResetToken(t, err)
}

func TestResetTokenNewerInvalidatesOlder(t *testing.T) {
	ctx := context.Background()
	m := newResetManager(t, NewMemoryResetStore(), &fakeClock{time.Now()})

	older, _ := m.Issue(ctx, "u-1")
	other, _ := m.Issue(ctx, "u-2")
	newer, _ := m.Issue(ctx, "u-1")
	_, err := m.Redeem(ctx, older)
	wantInvalidResetToken(t, err)
	if subject, err := m.Redeem(ctx, newer); err != nil || subject != "u-1" {
		t.Fatalf("Redeem(newer) = %q, %v", subject, err)
	}
	if subject, err := m.Redeem(ctx, other); err != nil || subject != "u-2" {
		t.Fatalf("another subject's token was invalidated: %q, %v", subject, err)
	}
}

func TestResetTokenRejectsMalformedBeforeStore(t *testing.T) {
	ctx := context.Background()
	store := &spyResetStore{MemoryResetStore: NewMemoryResetStore()}
	m := newResetManager(t, store, &fakeClock{time.Now()})
	token, _ := m.Issue(ctx, "u-1")

	// The last character of 32 encoded bytes has two unused low bits.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, token[len(token)-1])
	nonCanonical := token[:len(token)-1] + string(alphabet[last^1])
	for _, bad := range []string{
		"",
		"short",
		token + "A",
		token[:len(token)-1],
		token + "=",
		strings.ReplaceAll(token, "-", "+") + "+",
		nonCanonical,
		" " + token,
		token[:20] + "\r\n" + token[20:],
		token[:20] + "\n" + token[20:],
	} {
		_, err := m.Redeem(ctx, bad)
		wantInvalidResetToken(t, err)
	}
	if store.takes != 0 {
		t.Fatalf("malformed tokens reached the store %d times", store.takes)
	}
	if subject, err := m.Redeem(ctx, token); err != nil || subject != "u-1" {
		t.Fatalf("malformed attempts consumed the real token: %q, %v", subject, err)
	}
	if _, err := m.Redeem(ctx, resetB64.EncodeToString(make([]byte, resetTokenBytes))); !errors.Is(err, ErrInvalidResetToken) {
		t.Fatalf("unknown token: %v", err)
	}
}

func TestResetTokenStoreErrors(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("db down")
	store := &spyResetStore{MemoryResetStore: NewMemoryResetStore(), takeErr: boom}
	m := newResetManager(t, store, &fakeClock{time.Now()})
	token, _ := m.Issue(ctx, "u-1")
	_, err := m.Redeem(ctx, token)
	if !errors.Is(err, boom) || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("Redeem with failing store = %v, want the store error", err)
	}

	m = newResetManager(t, failingPutStore{boom}, &fakeClock{time.Now()})
	if token, err := m.Issue(ctx, "u-1"); !errors.Is(err, boom) || token != "" {
		t.Fatalf("Issue with failing store = %q, %v", token, err)
	}
}

type failingPutStore struct{ err error }

func (s failingPutStore) PutResetToken(context.Context, ResetToken) error { return s.err }

func (s failingPutStore) TakeResetToken(context.Context, [sha256.Size]byte) (ResetToken, error) {
	return ResetToken{}, ErrResetTokenNotFound
}

type racyResetStore struct {
	*MemoryResetStore
	read sync.WaitGroup
}

func (s *racyResetStore) TakeResetToken(ctx context.Context, hash [sha256.Size]byte) (ResetToken, error) {
	s.mu.Lock()
	t, ok := s.byHash[hash]
	s.mu.Unlock()
	s.read.Done()
	s.read.Wait()
	if !ok {
		return ResetToken{}, ErrResetTokenNotFound
	}
	_, _ = s.MemoryResetStore.TakeResetToken(ctx, hash)
	return t, nil
}

func concurrentRedemptions(t *testing.T, store ResetTokenStore, n int) int {
	t.Helper()
	ctx := context.Background()
	m := newResetManager(t, store, &fakeClock{time.Now()})
	token, err := m.Issue(ctx, "u-1")
	if err != nil {
		t.Fatal(err)
	}
	var (
		wg        sync.WaitGroup
		start     = make(chan struct{})
		mu        sync.Mutex
		successes int
	)
	for range n {
		wg.Go(func() {
			<-start
			_, err := m.Redeem(ctx, token)
			switch {
			case err == nil:
				mu.Lock()
				successes++
				mu.Unlock()
			case !errors.Is(err, ErrInvalidResetToken):
				t.Errorf("Redeem = %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	return successes
}

func TestResetTokenConcurrentRedeemSucceedsOnce(t *testing.T) {
	const n = 64
	if got := concurrentRedemptions(t, NewMemoryResetStore(), n); got != 1 {
		t.Fatalf("MemoryResetStore: %d concurrent redemptions succeeded, want 1", got)
	}
	racy := &racyResetStore{MemoryResetStore: NewMemoryResetStore()}
	racy.read.Add(n)
	if got := concurrentRedemptions(t, racy, n); got != n {
		t.Fatalf("the check missed a non-atomic store: %d of %d redemptions succeeded", got, n)
	}
}

func TestNewResetManagerRejectsInvalidConfiguration(t *testing.T) {
	store := NewMemoryResetStore()
	for name, tc := range map[string]struct {
		store ResetTokenStore
		opts  []ResetOption
	}{
		"nil store":    {nil, nil},
		"zero TTL":     {store, []ResetOption{WithResetTTL(0)}},
		"negative TTL": {store, []ResetOption{WithResetTTL(-time.Minute)}},
		"nil clock":    {store, []ResetOption{WithResetClock(nil)}},
	} {
		if _, err := NewResetManager(tc.store, tc.opts...); err == nil {
			t.Errorf("%s: NewResetManager succeeded", name)
		}
	}
	m, err := NewResetManager(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Issue(context.Background(), ""); err == nil {
		t.Fatal("Issue accepted an empty subject")
	}
}

func FuzzRedeemResetToken(f *testing.F) {
	m, err := NewResetManager(NewMemoryResetStore())
	if err != nil {
		f.Fatal(err)
	}
	token, err := m.Issue(context.Background(), "u-1")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(token + "A")
	f.Add(token[:len(token)-1])
	f.Add(strings.Repeat("A", 43))
	f.Fuzz(func(t *testing.T, s string) {
		if s == token {
			return
		}
		if _, err := m.Redeem(context.Background(), s); !errors.Is(err, ErrInvalidResetToken) {
			t.Fatalf("Redeem(%q) = %v, want ErrInvalidResetToken", s, err)
		}
	})
}
