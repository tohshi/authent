package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// countingStore records calls to the wrapped store.
type countingStore struct {
	*MemoryStore
	mu    sync.Mutex
	saves int
	keys  []string
}

func (c *countingStore) Save(ctx context.Context, key string, s Session, exp time.Time) error {
	c.mu.Lock()
	c.saves++
	c.keys = append(c.keys, key)
	c.mu.Unlock()
	return c.MemoryStore.Save(ctx, key, s, exp)
}

func setup(t *testing.T, opts ...Option) (*Manager, *countingStore, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	mem := NewMemoryStore()
	mem.now = c.now
	store := &countingStore{MemoryStore: mem}
	m, err := NewManager(store, append([]Option{
		WithClock(c.now), WithIdleTimeout(30 * time.Minute), WithAbsoluteTimeout(8 * time.Hour),
	}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return m, store, c
}

var alice = authent.Principal{Subject: "alice", Method: authent.MethodPassword}

func TestCreateAndGet(t *testing.T) {
	m, store, c := setup(t)
	ctx := context.Background()
	token, s, err := m.Create(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 43 || s.CSRFToken == "" || s.CSRFToken == token {
		t.Fatalf("token %q csrf %q", token, s.CSRFToken)
	}
	for _, k := range store.keys {
		if strings.Contains(k, token) {
			t.Fatal("raw token reached the store")
		}
	}

	got, err := m.Get(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	p := got.Principal()
	if p.Subject != "alice" || p.Method != authent.MethodSession || !p.AuthTime.Equal(c.now()) {
		t.Fatalf("principal = %+v", p)
	}
	if p.Claims["auth_method"] != "password" {
		t.Fatalf("claims = %v", p.Claims)
	}
}

func TestGetRejectsBadTokens(t *testing.T) {
	m, _, _ := setup(t)
	ctx := context.Background()
	token, _, _ := m.Create(ctx, alice)
	other, _ := newToken()
	for _, tok := range []string{"", "short", token + "A", token[:42], other, strings.ToUpper(token), token + "\n"} {
		if _, err := m.Get(ctx, tok); !errors.Is(err, ErrInvalidSession) || !errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("Get(%q) = %v, want ErrInvalidSession", tok, err)
		}
	}
}

func TestIdleTimeout(t *testing.T) {
	m, store, c := setup(t)
	ctx := context.Background()
	token, _, _ := m.Create(ctx, alice)

	// Activity keeps the session alive past the idle timeout.
	for range 4 {
		c.advance(20 * time.Minute)
		if _, err := m.Get(ctx, token); err != nil {
			t.Fatalf("active session expired: %v", err)
		}
	}
	c.advance(31 * time.Minute)
	if _, err := m.Get(ctx, token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("idle session err = %v", err)
	}
	if store.Len() != 0 {
		t.Fatal("expired session not deleted")
	}
}

func TestAbsoluteTimeout(t *testing.T) {
	m, _, c := setup(t)
	ctx := context.Background()
	token, _, _ := m.Create(ctx, alice)
	for range 7 * 4 {
		c.advance(15 * time.Minute)
		if _, err := m.Get(ctx, token); err != nil {
			t.Fatalf("session expired early: %v", err)
		}
	}
	c.advance(time.Hour + time.Second)
	if _, err := m.Get(ctx, token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("err = %v, want expiry at absolute timeout", err)
	}
}

func TestTouchInterval(t *testing.T) {
	m, store, c := setup(t, WithTouchInterval(time.Minute))
	ctx := context.Background()
	token, _, _ := m.Create(ctx, alice)
	base := store.saves
	for range 10 {
		c.advance(time.Second)
		_, _ = m.Get(ctx, token)
	}
	if store.saves != base {
		t.Fatalf("saves = %d, want no writes within touch interval", store.saves-base)
	}
	c.advance(time.Minute)
	_, _ = m.Get(ctx, token)
	if store.saves != base+1 {
		t.Fatalf("saves = %d, want 1 touch", store.saves-base)
	}
}

func TestSaveValues(t *testing.T) {
	m, _, _ := setup(t)
	ctx := context.Background()
	token, s, _ := m.Create(ctx, alice)
	s.Values["cart"] = "42"
	if err := m.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Values["cart"] = "mutated without save"
	got, _ := m.Get(ctx, token)
	if got.Values["cart"] != "42" {
		t.Fatalf("Values = %v", got.Values)
	}
	if err := m.Save(ctx, &Session{}); err == nil {
		t.Fatal("Save of foreign session succeeded")
	}
}

func TestRotate(t *testing.T) {
	m, _, c := setup(t)
	ctx := context.Background()
	token, s, _ := m.Create(ctx, alice)
	s.Values["k"] = "v"
	_ = m.Save(ctx, s)
	created := s.CreatedAt

	c.advance(time.Minute)
	newTok, rotated, err := m.Rotate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if newTok == token || rotated.CSRFToken == s.CSRFToken {
		t.Fatal("token or CSRF token not replaced")
	}
	if _, err := m.Get(ctx, token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("old token still valid: %v", err)
	}
	got, err := m.Get(ctx, newTok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Values["k"] != "v" || !got.CreatedAt.Equal(created) {
		t.Fatalf("rotated session lost data: %+v", got)
	}
}

func TestDestroy(t *testing.T) {
	m, _, _ := setup(t)
	ctx := context.Background()
	token, _, _ := m.Create(ctx, alice)
	if err := m.Destroy(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("err = %v", err)
	}
	if err := m.Destroy(ctx, "garbage"); err != nil {
		t.Fatalf("Destroy(garbage) = %v", err)
	}
}

func TestVerifyCSRF(t *testing.T) {
	m, _, _ := setup(t)
	_, s, _ := m.Create(context.Background(), alice)
	if !s.VerifyCSRF(s.CSRFToken) {
		t.Fatal("valid CSRF token rejected")
	}
	for _, bad := range []string{"", "x", s.CSRFToken + "x"} {
		if s.VerifyCSRF(bad) {
			t.Errorf("VerifyCSRF(%q) = true", bad)
		}
	}
	if (&Session{}).VerifyCSRF("") {
		t.Fatal("empty CSRF token accepted")
	}
}

func TestStoreErrorIsNotUnauthenticated(t *testing.T) {
	boom := errors.New("redis down")
	m, err := NewManager(failingStore{boom})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := newToken()
	_, err = m.Get(context.Background(), tok)
	if !errors.Is(err, boom) || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("err = %v", err)
	}
}

type failingStore struct{ err error }

func (f failingStore) Load(context.Context, string) (Session, error)          { return Session{}, f.err }
func (f failingStore) Save(context.Context, string, Session, time.Time) error { return f.err }
func (f failingStore) Delete(context.Context, string) error                   { return f.err }

func TestNewManagerValidates(t *testing.T) {
	for _, opts := range [][]Option{
		{WithIdleTimeout(0)},
		{WithAbsoluteTimeout(-time.Second)},
		{WithIdleTimeout(time.Minute), WithTouchInterval(time.Minute)},
	} {
		if _, err := NewManager(NewMemoryStore(), opts...); err == nil {
			t.Error("NewManager succeeded with invalid options")
		}
	}
	if _, err := NewManager(nil); err == nil {
		t.Error("NewManager(nil) succeeded")
	}
}

func TestMemoryStoreDeleteExpired(t *testing.T) {
	m, store, c := setup(t)
	ctx := context.Background()
	for range 3 {
		_, _, _ = m.Create(ctx, alice)
	}
	c.advance(time.Hour)
	store.DeleteExpired()
	if store.Len() != 0 {
		t.Fatalf("Len = %d", store.Len())
	}
}
