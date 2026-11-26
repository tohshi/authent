package session

import (
	"context"
	"errors"
	"slices"
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
	if len(token) != 43 || s.CSRFToken() == "" || s.CSRFToken() == token {
		t.Fatalf("token %q csrf %q", token, s.CSRFToken())
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
	if amr, _ := p.Claims["amr"].([]string); !slices.Equal(amr, []string{"password"}) {
		t.Fatalf("claims = %v", p.Claims)
	}
	if f := got.Factors(); len(f) != 1 || f[0].Method != authent.MethodPassword || !f[0].Time.Equal(c.now()) {
		t.Fatalf("Factors = %+v", f)
	}
}

func TestCreateRejectsIncompletePrincipal(t *testing.T) {
	m, store, _ := setup(t)
	for _, p := range []authent.Principal{
		{Method: authent.MethodPassword},
		{Subject: "alice"},
	} {
		if _, _, err := m.Create(context.Background(), p); err == nil {
			t.Errorf("Create(%+v) succeeded", p)
		}
	}
	if store.Len() != 0 {
		t.Fatal("a rejected Create stored a session")
	}
}

func TestCreateFactorTime(t *testing.T) {
	m, _, c := setup(t)
	ctx := context.Background()
	earlier := c.now().Add(-time.Hour)
	for _, tc := range []struct {
		authTime, want time.Time
	}{
		{earlier, earlier},
		{time.Time{}, c.now()},
		// An authenticator's clock ahead of ours must not make the
		// authentication look fresher than it can be.
		{c.now().Add(time.Hour), c.now()},
	} {
		_, s, err := m.Create(ctx, authent.Principal{Subject: "alice", Method: authent.MethodOIDC, AuthTime: tc.authTime})
		if err != nil {
			t.Fatal(err)
		}
		if f := s.Factors(); !f[0].Time.Equal(tc.want) || !s.Principal().AuthTime.Equal(tc.want) {
			t.Errorf("AuthTime %v: factor time %v, want %v", tc.authTime, f[0].Time, tc.want)
		}
	}
}

func TestStepUp(t *testing.T) {
	m, _, c := setup(t)
	ctx := context.Background()
	t0 := c.now()
	token, s, _ := m.Create(ctx, alice)
	set(t, s, "k", "v")
	_ = m.Save(ctx, s)

	c.advance(10 * time.Minute)
	t1 := c.now()
	if s.AuthenticatedSince(t1.Add(-5*time.Minute), authent.MethodTOTP) {
		t.Fatal("TOTP required before step-up, but AuthenticatedSince reported true")
	}
	newTok, up, err := m.StepUp(ctx, token, authent.Principal{Subject: "alice", Method: authent.MethodTOTP})
	if err != nil {
		t.Fatal(err)
	}
	if newTok == token || up.CSRFToken() == s.CSRFToken() {
		t.Fatal("StepUp did not rotate the token and CSRF token")
	}
	if _, err := m.Get(ctx, token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("token from before the step-up still valid: %v", err)
	}
	got, err := m.Get(ctx, newTok)
	if err != nil {
		t.Fatal(err)
	}
	want := []Factor{{authent.MethodPassword, t0}, {authent.MethodTOTP, t1}}
	if f := got.Factors(); len(f) != 2 || f[0].Method != want[0].Method || !f[0].Time.Equal(t0) ||
		f[1].Method != want[1].Method || !f[1].Time.Equal(t1) {
		t.Fatalf("Factors = %+v, want %+v", f, want)
	}
	p := got.Principal()
	if amr, _ := p.Claims["amr"].([]string); !slices.Equal(amr, []string{"password", "totp"}) || !p.AuthTime.Equal(t1) {
		t.Fatalf("Principal = %+v", p)
	}
	if !got.AuthenticatedSince(t1.Add(-5*time.Minute), authent.MethodTOTP) ||
		!got.AuthenticatedSince(time.Time{}, authent.MethodPassword, authent.MethodTOTP) {
		t.Fatal("AuthenticatedSince does not see the step-up")
	}
	if get(got, "k") != "v" || !got.CreatedAt().Equal(t0) {
		t.Fatal("StepUp lost the values or reset the absolute timeout")
	}

	// Passing a method again refreshes its time without duplicating it.
	c.advance(time.Minute)
	newTok, again, err := m.StepUp(ctx, newTok, authent.Principal{Subject: "alice", Method: authent.MethodPassword})
	if err != nil {
		t.Fatal(err)
	}
	if f := again.Factors(); len(f) != 2 || f[0].Method != authent.MethodPassword || !f[0].Time.Equal(c.now()) {
		t.Fatalf("Factors after re-authentication = %+v", f)
	}
	if _, err := m.Get(ctx, newTok); err != nil {
		t.Fatal(err)
	}
}

func TestStepUpRejectsOtherPrincipal(t *testing.T) {
	m, store, _ := setup(t)
	ctx := context.Background()
	token, _, _ := m.Create(ctx, authent.Principal{Subject: "alice", Issuer: "https://idp.example", Method: authent.MethodOIDC})
	for _, p := range []authent.Principal{
		{Subject: "mallory", Issuer: "https://idp.example", Method: authent.MethodTOTP},
		{Subject: "alice", Method: authent.MethodTOTP},
		{Subject: "alice", Issuer: "https://other.example", Method: authent.MethodTOTP},
		{Subject: "Alice", Issuer: "https://idp.example", Method: authent.MethodTOTP},
		{Subject: "alice", Issuer: "https://idp.example"},
	} {
		if _, _, err := m.StepUp(ctx, token, p); !errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("StepUp(%+v): err = %v, want ErrUnauthenticated", p, err)
		}
	}
	s, err := m.Get(ctx, token)
	if err != nil {
		t.Fatalf("session after rejected step-ups: %v", err)
	}
	if f := s.Factors(); len(f) != 1 || store.Len() != 1 {
		t.Fatalf("rejected step-ups changed the session: %+v, %d stored", f, store.Len())
	}
	if _, _, err := m.StepUp(ctx, "garbage", alice); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("StepUp(garbage): err = %v", err)
	}
}

func TestAuthenticatedSince(t *testing.T) {
	m, _, c := setup(t)
	ctx := context.Background()
	t0 := c.now()
	token, _, _ := m.Create(ctx, alice)
	c.advance(20 * time.Minute)
	t1 := c.now()
	_, s, err := m.StepUp(ctx, token, authent.Principal{Subject: "alice", Method: authent.MethodWebAuthn})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		since   time.Time
		methods []authent.Method
		want    bool
	}{
		{time.Time{}, nil, true},
		{t1, nil, true},
		{t1.Add(time.Nanosecond), nil, false},
		{t0, []authent.Method{authent.MethodPassword}, true},
		{t0.Add(time.Nanosecond), []authent.Method{authent.MethodPassword}, false},
		{t1, []authent.Method{authent.MethodWebAuthn}, true},
		{t0, []authent.Method{authent.MethodPassword, authent.MethodWebAuthn}, true},
		{t1, []authent.Method{authent.MethodPassword, authent.MethodWebAuthn}, false},
		{time.Time{}, []authent.Method{authent.MethodTOTP}, false},
		{time.Time{}, []authent.Method{authent.MethodWebAuthn, authent.MethodTOTP}, false},
	} {
		if got := s.AuthenticatedSince(tc.since, tc.methods...); got != tc.want {
			t.Errorf("AuthenticatedSince(%v, %v) = %v, want %v", tc.since.Sub(t0), tc.methods, got, tc.want)
		}
	}
}

func TestFactorsReturnsCopy(t *testing.T) {
	m, _, _ := setup(t)
	_, s, _ := m.Create(context.Background(), alice)
	s.Factors()[0].Method = authent.MethodWebAuthn
	if s.AuthenticatedSince(time.Time{}, authent.MethodWebAuthn) {
		t.Fatal("modifying the result of Factors added a factor")
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
	created := s.CreatedAt()

	c.advance(time.Minute)
	newTok, rotated, err := m.Rotate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if newTok == token || rotated.CSRFToken() == s.CSRFToken() {
		t.Fatal("token or CSRF token not replaced")
	}
	if _, err := m.Get(ctx, token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("old token still valid: %v", err)
	}
	got, err := m.Get(ctx, newTok)
	if err != nil {
		t.Fatal(err)
	}
	if get(got, "k") != "v" || !got.CreatedAt().Equal(created) {
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
	if !s.VerifyCSRF(s.CSRFToken()) {
		t.Fatal("valid CSRF token rejected")
	}
	for _, bad := range []string{"", "x", s.CSRFToken() + "x"} {
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
	ctx := context.Background()
	tok, _ := newToken()
	handle, _ := storeKey(tok)
	for name, call := range map[string]func() error{
		"Create":    func() error { _, _, err := m.Create(ctx, alice); return err },
		"Get":       func() error { _, err := m.Get(ctx, tok); return err },
		"Rotate":    func() error { _, _, err := m.Rotate(ctx, tok); return err },
		"StepUp":    func() error { _, _, err := m.StepUp(ctx, tok, alice); return err },
		"Destroy":   func() error { return m.Destroy(ctx, tok) },
		"List":      func() error { _, err := m.List(ctx, "alice"); return err },
		"Revoke":    func() error { return m.Revoke(ctx, "alice", handle) },
		"RevokeAll": func() error { return m.RevokeAll(ctx, "alice") },
	} {
		if err := call(); !errors.Is(err, boom) || errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want the store error", name, err)
		}
	}
}

type failingStore struct{ err error }

func (f failingStore) Load(context.Context, string) (Record, error)            { return Record{}, f.err }
func (f failingStore) Save(context.Context, string, Record) error              { return f.err }
func (f failingStore) Delete(context.Context, string, uint64) error            { return f.err }
func (f failingStore) List(context.Context, string) (map[string]Record, error) { return nil, f.err }
func (f failingStore) DeleteSubject(context.Context, string) error             { return f.err }

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

func TestRevokeAllRacingStepUp(t *testing.T) {
	m, store, _ := setup(t)
	ctx := context.Background()
	token, _, _ := m.Create(ctx, alice)
	store.beforeDelete = func(string, uint64) {
		if err := m.RevokeAll(ctx, "alice"); err != nil {
			t.Error(err)
		}
	}
	if _, _, err := m.StepUp(ctx, token, authent.Principal{Subject: "alice", Method: authent.MethodTOTP}); err == nil {
		t.Fatal("StepUp of a session revoked meanwhile succeeded")
	}
	if store.Len() != 0 {
		t.Fatalf("store holds %d sessions; the stepped-up copy outlived RevokeAll", store.Len())
	}
}

func TestListOrderAndHandles(t *testing.T) {
	m, _, c := setup(t)
	ctx := context.Background()
	var tokens []string
	for range 3 {
		tok, _, _ := m.Create(ctx, alice)
		tokens = append(tokens, tok)
		c.advance(time.Second)
	}
	list, err := m.List(ctx, "alice")
	if err != nil || len(list) != 3 {
		t.Fatalf("List = %d sessions, %v", len(list), err)
	}
	for i, s := range list {
		if key, _ := storeKey(tokens[i]); s.Handle() != key || s.Handle() == tokens[i] {
			t.Errorf("session %d: handle %q does not identify token %d without revealing it", i, s.Handle(), i)
		}
	}
}

func TestListHidesCSRFToken(t *testing.T) {
	m, _, _ := setup(t)
	ctx := context.Background()
	token, s, _ := m.Create(ctx, alice)
	csrf := s.CSRFToken()
	list, err := m.List(ctx, "alice")
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %d sessions, %v", len(list), err)
	}
	listed := list[0]
	if listed.CSRFToken() != "" || listed.VerifyCSRF(csrf) || listed.VerifyCSRF("") {
		t.Fatal("a listed session reveals or accepts the CSRF token")
	}
	// Saving the listed copy would store its blank CSRF token.
	set(t, listed, "k", "v")
	if err := m.Save(ctx, listed); err == nil {
		t.Fatal("Save of a listed session succeeded")
	}
	got, err := m.Get(ctx, token)
	if err != nil || !got.VerifyCSRF(csrf) || get(got, "k") != "" {
		t.Fatalf("session after a rejected save of its listed copy: %v", err)
	}
}

// FuzzRevoke checks that no handle a client sends can end another
// subject's session or reach the store unless it is well formed.
func FuzzRevoke(f *testing.F) {
	ctx := context.Background()
	store := &countingStore{MemoryStore: NewMemoryStore()}
	m, _ := NewManager(store)
	victim, s, _ := m.Create(ctx, alice)
	f.Add(s.Handle())
	f.Add(victim)
	f.Add(s.Handle() + "=")
	f.Add("")
	f.Fuzz(func(t *testing.T, handle string) {
		loads := 0
		wrapped := &loadCounter{Store: store, loads: &loads}
		mm, _ := NewManager(wrapped)
		if err := mm.Revoke(ctx, "mallory", handle); err != nil {
			t.Fatalf("Revoke(%q) = %v", handle, err)
		}
		if _, err := m.Get(ctx, victim); err != nil {
			t.Fatalf("Revoke(mallory, %q) ended alice's session: %v", handle, err)
		}
		if _, ok := decodeToken(handle); !ok && loads != 0 {
			t.Fatalf("malformed handle %q reached the store", handle)
		}
	})
}

type loadCounter struct {
	Store
	loads *int
}

func (l *loadCounter) Load(ctx context.Context, key string) (Record, error) {
	*l.loads++
	return l.Store.Load(ctx, key)
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
