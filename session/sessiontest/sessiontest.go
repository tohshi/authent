// Package sessiontest provides a conformance test suite for session.Store
// implementations.
//
// Use it to test your own store, or to check session.SQLStore against your
// database and driver:
//
//	func TestStore(t *testing.T) {
//		sessiontest.TestStore(t, func(t *testing.T) session.Store {
//			return newEmptyStore(t)
//		})
//	}
package sessiontest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/session"
)

// TestStore runs the conformance suite as subtests of t. newStore must
// return a new, empty store on every call; it may use t.Cleanup to release
// it. The suite uses the real clock and takes a few seconds.
func TestStore(t *testing.T, newStore func(t *testing.T) session.Store) {
	tests := []struct {
		name string
		fn   func(*testing.T, session.Store)
	}{
		{"Empty", testEmpty},
		{"SaveAndLoad", testSaveAndLoad},
		{"DataIsCopied", testDataIsCopied},
		{"Versions", testVersions},
		{"Delete", testDelete},
		{"Expiry", testExpiry},
		{"ConcurrentSaves", testConcurrentSaves},
		{"Manager", testManager},
		{"ManagerConcurrentGets", testManagerConcurrentGets},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.fn(t, newStore(t))
		})
	}
}

var ctx = context.Background()

// newKey returns a key in the format the Manager uses.
func newKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func record(version uint64, data string) session.Record {
	return session.Record{Version: version, ExpiresAt: time.Now().Add(time.Hour), Data: []byte(data)}
}

func save(t *testing.T, s session.Store, key string, r session.Record) {
	t.Helper()
	if err := s.Save(ctx, key, r); err != nil {
		t.Fatalf("Save(version %d): %v", r.Version, err)
	}
}

func wantConflict(t *testing.T, err error, op string) {
	t.Helper()
	if !errors.Is(err, session.ErrConflict) {
		t.Errorf("%s: err = %v, want ErrConflict", op, err)
	}
}

func wantRecord(t *testing.T, s session.Store, key string, want session.Record) {
	t.Helper()
	got, err := s.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != want.Version || !got.ExpiresAt.Equal(want.ExpiresAt) || !bytes.Equal(got.Data, want.Data) {
		t.Errorf("Load = {%d %v %q}, want {%d %v %q}",
			got.Version, got.ExpiresAt, got.Data, want.Version, want.ExpiresAt, want.Data)
	}
}

func wantNotFound(t *testing.T, s session.Store, key string) {
	t.Helper()
	if _, err := s.Load(ctx, key); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("Load: err = %v, want ErrNotFound", err)
	}
}

func testEmpty(t *testing.T, s session.Store) {
	key := newKey()
	wantNotFound(t, s, key)
	if err := s.Delete(ctx, key, 0); err != nil {
		t.Errorf("Delete(unknown, 0) = %v", err)
	}
	wantConflict(t, s.Delete(ctx, key, 1), "Delete(unknown, 1)")
	wantNotFound(t, s, key)
}

func testSaveAndLoad(t *testing.T, s session.Store) {
	a, b := newKey(), newKey()
	// Data is opaque bytes, not necessarily text.
	ra := session.Record{Version: 1, ExpiresAt: time.Now().Add(time.Hour), Data: []byte("{\"a\":1}\x00\xff\xfe")}
	rb := session.Record{Version: 1, ExpiresAt: time.Now().Add(2 * time.Hour), Data: bytes.Repeat([]byte("b"), 1<<16)}
	save(t, s, a, ra)
	save(t, s, b, rb)
	wantRecord(t, s, a, ra)
	wantRecord(t, s, b, rb)
}

func testDataIsCopied(t *testing.T, s session.Store) {
	key := newKey()
	data := []byte("original")
	save(t, s, key, session.Record{Version: 1, ExpiresAt: time.Now().Add(time.Hour), Data: data})
	copy(data, "mutated!")
	got, err := s.Load(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "original" {
		t.Fatalf("Data = %q after the caller mutated the saved slice", got.Data)
	}
	copy(got.Data, "mutated!")
	if got, _ := s.Load(ctx, key); string(got.Data) != "original" {
		t.Fatalf("Data = %q after the caller mutated a loaded slice", got.Data)
	}
}

func testVersions(t *testing.T, s session.Store) {
	key := newKey()
	v1 := record(1, "v1")
	save(t, s, key, v1)
	wantConflict(t, s.Save(ctx, key, record(1, "again")), "Save(version 1) over an existing key")
	wantConflict(t, s.Save(ctx, key, record(3, "skip")), "Save(version 3) over version 1")
	wantConflict(t, s.Save(ctx, key, record(0, "zero")), "Save(version 0)")
	wantRecord(t, s, key, v1)

	v2 := record(2, "v2")
	save(t, s, key, v2)
	wantConflict(t, s.Save(ctx, key, record(2, "stale")), "Save(version 2) over version 2")
	wantRecord(t, s, key, v2)
	save(t, s, key, record(3, "v3"))

	other := newKey()
	wantConflict(t, s.Save(ctx, other, record(2, "missing")), "Save(version 2) of an unknown key")
	wantNotFound(t, s, other)
}

func testDelete(t *testing.T, s session.Store) {
	key := newKey()
	v2 := record(2, "v2")
	save(t, s, key, record(1, "v1"))
	save(t, s, key, v2)
	wantConflict(t, s.Delete(ctx, key, 1), "Delete(stale version)")
	wantConflict(t, s.Delete(ctx, key, 3), "Delete(future version)")
	wantRecord(t, s, key, v2)
	if err := s.Delete(ctx, key, 2); err != nil {
		t.Fatalf("Delete(current version) = %v", err)
	}
	wantNotFound(t, s, key)
	wantConflict(t, s.Delete(ctx, key, 2), "Delete(deleted key, 2)")
	wantConflict(t, s.Save(ctx, key, record(3, "v3")), "Save(version 3) of a deleted key")

	other := newKey()
	save(t, s, other, record(1, "v1"))
	if err := s.Delete(ctx, other, 0); err != nil {
		t.Fatalf("Delete(key, 0) = %v", err)
	}
	wantNotFound(t, s, other)
}

func testExpiry(t *testing.T, s session.Store) {
	past := newKey()
	save(t, s, past, session.Record{Version: 1, ExpiresAt: time.Now().Add(-time.Second), Data: []byte("x")})
	wantNotFound(t, s, past)
	wantConflict(t, s.Delete(ctx, past, 1), "Delete of an expired record")

	updated := newKey()
	save(t, s, updated, record(1, "v1"))
	save(t, s, updated, session.Record{Version: 2, ExpiresAt: time.Now().Add(-time.Second), Data: []byte("v2")})
	wantNotFound(t, s, updated)

	timed := newKey()
	exp := time.Now().Add(time.Second)
	save(t, s, timed, session.Record{Version: 1, ExpiresAt: exp, Data: []byte("x")})
	if _, err := s.Load(ctx, timed); err != nil {
		t.Fatalf("Load before expiry: %v", err)
	}
	time.Sleep(time.Until(exp) + 200*time.Millisecond)
	wantNotFound(t, s, timed)
	wantConflict(t, s.Save(ctx, timed, record(2, "v2")), "Save over an expired record")
	wantNotFound(t, s, timed)
}

func testConcurrentSaves(t *testing.T, s session.Store) {
	key := newKey()
	save(t, s, key, record(1, "start"))
	const workers, attempts = 8, 20
	var (
		mu   sync.Mutex
		wins = map[uint64]int{}
		wg   sync.WaitGroup
	)
	for range workers {
		wg.Go(func() {
			for range attempts {
				r, err := s.Load(ctx, key)
				if err != nil {
					t.Errorf("Load: %v", err)
					return
				}
				r.Version++
				r.Data = append(r.Data, '.')
				err = s.Save(ctx, key, r)
				if errors.Is(err, session.ErrConflict) {
					continue
				}
				if err != nil {
					t.Errorf("Save: %v", err)
					return
				}
				mu.Lock()
				wins[r.Version]++
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	final, err := s.Load(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	// Each version was written by exactly one successful Save, so no
	// update was lost.
	for v := uint64(2); v <= final.Version; v++ {
		if wins[v] != 1 {
			t.Errorf("version %d written by %d saves, want 1", v, wins[v])
		}
	}
	if len(wins) != int(final.Version-1) || len(final.Data) != len("start")+len(wins) {
		t.Errorf("final version %d with %d bytes after %d successful saves", final.Version, len(final.Data), len(wins))
	}
}

func newManager(t *testing.T, s session.Store, opts ...session.Option) *session.Manager {
	t.Helper()
	m, err := session.NewManager(s, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

var alice = authent.Principal{Subject: "alice", Method: authent.MethodPassword}

var cartKey = session.Key[string]("cart")

func set(t *testing.T, s *session.Session, v string) {
	t.Helper()
	if err := cartKey.Set(s, v); err != nil {
		t.Fatal(err)
	}
}

func cart(s *session.Session) string {
	v, _, _ := cartKey.Get(s)
	return v
}

func testManager(t *testing.T, s session.Store) {
	m := newManager(t, s)
	token, created, err := m.Create(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	set(t, created, "42")
	if err := m.Save(ctx, created); err != nil {
		t.Fatal(err)
	}

	a, err := m.Get(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := m.Get(ctx, token)
	if a.Subject != "alice" || cart(a) != "42" || a.CSRFToken != created.CSRFToken {
		t.Fatalf("Get = %+v", a)
	}
	set(t, a, "a")
	if err := m.Save(ctx, a); err != nil {
		t.Fatal(err)
	}
	set(t, b, "b")
	err = m.Save(ctx, b)
	if !errors.Is(err, session.ErrConflict) || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("Save of a stale copy: err = %v, want ErrConflict", err)
	}
	if got, _ := m.Get(ctx, token); cart(got) != "a" {
		t.Fatalf("cart = %q after a rejected save", cart(got))
	}

	newToken, rotated, err := m.Rotate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, token); !errors.Is(err, session.ErrInvalidSession) {
		t.Fatalf("Get(old token) after Rotate: err = %v", err)
	}
	if err := m.Save(ctx, a); !errors.Is(err, session.ErrConflict) {
		t.Fatalf("Save of a rotated-away copy: err = %v, want ErrConflict", err)
	}
	if got, err := m.Get(ctx, newToken); err != nil || cart(got) != "a" || got.CSRFToken != rotated.CSRFToken {
		t.Fatalf("Get(new token) = %+v, %v", got, err)
	}

	if err := m.Destroy(ctx, newToken); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, newToken); !errors.Is(err, session.ErrInvalidSession) {
		t.Fatalf("Get after Destroy: err = %v", err)
	}
	if err := m.Save(ctx, rotated); !errors.Is(err, session.ErrConflict) {
		t.Fatalf("Save after Destroy: err = %v, want ErrConflict", err)
	}
}

func testManagerConcurrentGets(t *testing.T, s session.Store) {
	// Every Get writes the activity time back, so concurrent Gets race to
	// save the same session. None of them may fail.
	m := newManager(t, s, session.WithTouchInterval(0))
	token, _, err := m.Create(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				if _, err := m.Get(ctx, token); err != nil {
					t.Errorf("Get: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
}
