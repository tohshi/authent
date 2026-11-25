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

// countingStore records calls to the wrapped store. Its hooks, if set,
// run before the matching call and simulate concurrent requests.
type countingStore struct {
	*MemoryStore
	mu    sync.Mutex
	saves int
	keys  []string

	beforeSave   func(key string, r Record)
	beforeDelete func(key string, version uint64)
}

func (c *countingStore) Save(ctx context.Context, key string, r Record) error {
	c.mu.Lock()
	c.saves++
	c.keys = append(c.keys, key)
	hook := c.beforeSave
	c.beforeSave = nil
	c.mu.Unlock()
	if hook != nil {
		hook(key, r)
	}
	return c.MemoryStore.Save(ctx, key, r)
}

func (c *countingStore) Delete(ctx context.Context, key string, version uint64) error {
	c.mu.Lock()
	hook := c.beforeDelete
	c.beforeDelete = nil
	c.mu.Unlock()
	if hook != nil {
		hook(key, version)
	}
	return c.MemoryStore.Delete(ctx, key, version)
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

func set(t *testing.T, s *Session, key, v string) {
	t.Helper()
	if err := Key[string](key).Set(s, v); err != nil {
		t.Fatal(err)
	}
}

func get(s *Session, key string) string {
	v, _, _ := Key[string](key).Get(s)
	return v
}

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
	set(t, s, "cart", "42")
	if err := m.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	set(t, s, "cart", "mutated without save")
	got, _ := m.Get(ctx, token)
	if get(got, "cart") != "42" {
		t.Fatalf("cart = %q", get(got, "cart"))
	}
	if err := m.Save(ctx, &Session{}); err == nil {
		t.Fatal("Save of foreign session succeeded")
	}
}

func TestRotate(t *testing.T) {
	m, _, c := setup(t)
	ctx := context.Background()
	token, s, _ := m.Create(ctx, alice)
	set(t, s, "k", "v")
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
	if get(got, "k") != "v" || !got.CreatedAt.Equal(created) {
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

func (f failingStore) Load(context.Context, string) (Record, error) { return Record{}, f.err }
func (f failingStore) Save(context.Context, string, Record) error   { return f.err }
func (f failingStore) Delete(context.Context, string, uint64) error { return f.err }

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

func TestSaveConflict(t *testing.T) {
	m, _, _ := setup(t)
	ctx := context.Background()
	token, _, _ := m.Create(ctx, alice)
	a, _ := m.Get(ctx, token)
	b, _ := m.Get(ctx, token)
	set(t, a, "k", "a")
	if err := m.Save(ctx, a); err != nil {
		t.Fatal(err)
	}
	set(t, b, "k", "b")
	if err := m.Save(ctx, b); !errors.Is(err, ErrConflict) || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("Save of a stale copy: err = %v, want ErrConflict", err)
	}
	got, _ := m.Get(ctx, token)
	if get(got, "k") != "a" {
		t.Fatalf("k = %q, want the first save", get(got, "k"))
	}
	set(t, got, "k", "c")
	if err := m.Save(ctx, got); err != nil {
		t.Fatalf("Save after reloading: %v", err)
	}
}

func TestSaveExpired(t *testing.T) {
	m, _, c := setup(t)
	ctx := context.Background()
	_, s, _ := m.Create(ctx, alice)
	c.advance(31 * time.Minute)
	set(t, s, "k", "v")
	if err := m.Save(ctx, s); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("Save of an idle-expired session: err = %v, want ErrInvalidSession", err)
	}
}

func TestGetTouchConflictUsesNewerCopy(t *testing.T) {
	m, store, c := setup(t)
	ctx := context.Background()
	token, _, _ := m.Create(ctx, alice)
	other, _ := m.Get(ctx, token)
	c.advance(2 * time.Minute)
	store.beforeSave = func(string, Record) {
		set(t, other, "k", "concurrent")
		if err := m.Save(ctx, other); err != nil {
			t.Error(err)
		}
	}
	got, err := m.Get(ctx, token)
	if err != nil {
		t.Fatalf("Get with a conflicting touch: %v", err)
	}
	if get(got, "k") != "concurrent" {
		t.Fatalf("k = %q, want the concurrent save", get(got, "k"))
	}
	set(t, got, "k", "next")
	if err := m.Save(ctx, got); err != nil {
		t.Fatalf("Save of the returned copy: %v", err)
	}
}

func TestRotateConflict(t *testing.T) {
	m, store, _ := setup(t)
	ctx := context.Background()
	token, _, _ := m.Create(ctx, alice)
	other, _ := m.Get(ctx, token)
	store.beforeDelete = func(string, uint64) {
		set(t, other, "k", "concurrent")
		if err := m.Save(ctx, other); err != nil {
			t.Error(err)
		}
	}
	if _, _, err := m.Rotate(ctx, token); !errors.Is(err, ErrConflict) {
		t.Fatalf("Rotate racing a save: err = %v, want ErrConflict", err)
	}
	got, err := m.Get(ctx, token)
	if err != nil || get(got, "k") != "concurrent" {
		t.Fatalf("old session after a failed Rotate = %+v, %v", got, err)
	}
	if store.Len() != 1 {
		t.Fatalf("store holds %d sessions, want only the original", store.Len())
	}
}

func TestRotateRacingDestroy(t *testing.T) {
	m, store, _ := setup(t)
	ctx := context.Background()
	token, _, _ := m.Create(ctx, alice)
	store.beforeDelete = func(string, uint64) {
		if err := m.Destroy(ctx, token); err != nil {
			t.Error(err)
		}
	}
	if _, _, err := m.Rotate(ctx, token); err == nil {
		t.Fatal("Rotate of a session destroyed meanwhile succeeded")
	}
	if store.Len() != 0 {
		t.Fatalf("store holds %d sessions; the rotated copy outlived Destroy", store.Len())
	}
}

func TestCorruptRecordIsNotUnauthenticated(t *testing.T) {
	store := NewMemoryStore()
	m, _ := NewManager(store)
	tok, _ := newToken()
	key, _ := storeKey(tok)
	_ = store.Save(context.Background(), key, Record{Version: 1, ExpiresAt: time.Now().Add(time.Hour), Data: []byte("{")})
	_, err := m.Get(context.Background(), tok)
	if err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("Get of a corrupt record: err = %v, want an infrastructure error", err)
	}
}

type cart struct {
	Items []string `json:"items"`
	Total int      `json:"total"`
}

func TestTypedValues(t *testing.T) {
	m, _, _ := setup(t)
	ctx := context.Background()
	token, s, _ := m.Create(ctx, alice)
	cartKey, countKey := Key[cart]("cart"), Key[int]("count")
	if v, ok, err := cartKey.Get(s); ok || err != nil || v.Items != nil {
		t.Fatalf("Get of a missing value = %+v, %v, %v", v, ok, err)
	}
	items := []string{"a", "b"}
	if err := cartKey.Set(s, cart{Items: items, Total: 3}); err != nil {
		t.Fatal(err)
	}
	items[0] = "changed after Set"
	if err := countKey.Set(s, 7); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(ctx, s); err != nil {
		t.Fatal(err)
	}

	got, _ := m.Get(ctx, token)
	c, ok, err := cartKey.Get(got)
	if !ok || err != nil || len(c.Items) != 2 || c.Items[0] != "a" || c.Items[1] != "b" || c.Total != 3 {
		t.Fatalf("cart = %+v, %v, %v", c, ok, err)
	}
	if n, ok, err := countKey.Get(got); !ok || err != nil || n != 7 {
		t.Fatalf("count = %v, %v, %v", n, ok, err)
	}
	// A value read as another type is an error, not a zero value.
	if _, ok, err := Key[int]("cart").Get(got); !ok || err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("Get as the wrong type = %v, %v", ok, err)
	}
	if err := Key[chan int]("ch").Set(got, make(chan int)); err == nil {
		t.Fatal("Set of an unencodable value succeeded")
	}

	cartKey.Delete(got)
	if err := m.Save(ctx, got); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Get(ctx, token)
	if _, ok, _ := cartKey.Get(got); ok {
		t.Fatal("deleted value still present")
	}
	if _, ok, _ := countKey.Get(got); !ok {
		t.Fatal("Delete removed another value")
	}
}
