package apikey

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type countingStore struct {
	*MemoryStore
	lookups int
	err     error
	rewrite func(Record) Record
}

func (s *countingStore) Lookup(ctx context.Context, id string) (Record, error) {
	s.lookups++
	if s.err != nil {
		return Record{}, s.err
	}
	r, err := s.MemoryStore.Lookup(ctx, id)
	if err == nil && s.rewrite != nil {
		r = s.rewrite(r)
	}
	return r, err
}

func newTestManager(t *testing.T, now *time.Time) (*Manager, *countingStore) {
	t.Helper()
	store := &countingStore{MemoryStore: NewMemoryStore()}
	m, err := NewManager("test", store, WithClock(func() time.Time { return *now }))
	if err != nil {
		t.Fatal(err)
	}
	return m, store
}

func TestCreateAndAuthenticate(t *testing.T) {
	now := t0
	m, _ := newTestManager(t, &now)
	key, rec, err := m.Create(t.Context(), "u1", t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "test_"+rec.ID+"_") {
		t.Fatalf("key %q does not start with prefix and ID %q", key, rec.ID)
	}
	now = t0.Add(time.Minute)
	p, err := m.Authenticate(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "u1" || p.Method != authent.MethodAPIKey || !p.AuthTime.Equal(now) || p.Claims["key_id"] != rec.ID {
		t.Fatalf("unexpected principal %+v", p)
	}

	other, _, _ := m.Create(t.Context(), "u1", t0.Add(time.Hour))
	if other == key {
		t.Fatal("two keys are equal")
	}
}

// The key was built with Python's base64.b32encode and zlib.crc32 from
// ID bytes 00..09 and secret bytes 10..2e; the hash is hashlib.sha256 of
// the secret bytes.
func TestIndependentVector(t *testing.T) {
	const (
		key  = "test_aaaqeayeaudaocaj_caireeyuculbogazdinryhi6d4qccirdeqssmjzifevcwlbnf32gdpqn"
		id   = "aaaqeayeaudaocaj"
		hash = "a753569871e133666b8207d3afdb1918da92f1ff47ee5516c76a41791a5e0799"
	)
	now := t0
	m, store := newTestManager(t, &now)
	r := Record{ID: id, Subject: "svc", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
	hex.Decode(r.SecretHash[:], []byte(hash))
	if err := store.Create(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	p, err := m.Authenticate(t.Context(), key)
	if err != nil || p.Subject != "svc" {
		t.Fatalf("Authenticate = %+v, %v", p, err)
	}
}

func TestMalformedKeysSkipTheStore(t *testing.T) {
	now := t0
	m, store := newTestManager(t, &now)
	key, _, err := m.Create(t.Context(), "u1", t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) string {
		b := []byte(key)
		if b[i] == 'a' {
			b[i] = 'b'
		} else {
			b[i] = 'a'
		}
		return string(b)
	}
	other, _ := NewManager("other", NewMemoryStore())
	otherKey, _, _ := other.Create(t.Context(), "u1", t0.Add(time.Hour))
	cases := map[string]string{
		"empty":            "",
		"typo in prefix":   flip(1),
		"typo in id":       flip(len("test_") + 3),
		"typo in secret":   flip(len("test_") + idLen + 1 + 10),
		"typo in checksum": flip(len(key) - 1),
		"truncated":        key[:len(key)-1],
		"extra character":  key + "a",
		"uppercase":        strings.ToUpper(key),
		"other prefix":     otherKey,
		"newline":          key[:30] + "\n" + key[31:],
		"swapped segments": "test_" + key[len(key)-idLen:] + "_" + key[len("test_"):len(key)-idLen],
		"padding":          key[:len(key)-1] + "=",
	}
	for name, k := range cases {
		_, err := m.Authenticate(t.Context(), k)
		if !errors.Is(err, ErrMalformed) || !errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
	if store.lookups != 0 {
		t.Fatalf("malformed keys caused %d store lookups", store.lookups)
	}
}

func TestRejectedKeys(t *testing.T) {
	now := t0
	m, store := newTestManager(t, &now)
	key, rec, err := m.Create(t.Context(), "u1", t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	id, secret, _ := parse("test", key)
	wrong := append([]byte(nil), secret...)
	wrong[0] ^= 1
	unknownID := strings.Repeat("a", idLen)

	cases := []struct {
		name    string
		key     string
		now     time.Time
		rewrite func(Record) Record
		want    error
	}{
		{name: "unknown id", key: format("test", unknownID, secret), now: t0, want: ErrInvalidKey},
		{name: "wrong secret", key: format("test", id, wrong), now: t0, want: ErrInvalidKey},
		{name: "expired", key: key, now: t0.Add(time.Hour), want: ErrExpired},
		{name: "no expiry stored", key: key, now: t0, want: ErrExpired,
			rewrite: func(r Record) Record { r.ExpiresAt = time.Time{}; return r }},
		{name: "record for another id", key: key, now: t0, want: ErrInvalidKey,
			rewrite: func(r Record) Record { r.ID = unknownID; return r }},
		{name: "record without subject", key: key, now: t0, want: ErrInvalidKey,
			rewrite: func(r Record) Record { r.Subject = ""; return r }},
	}
	for _, c := range cases {
		now, store.rewrite = c.now, c.rewrite
		_, err := m.Authenticate(t.Context(), c.key)
		if !errors.Is(err, c.want) || !errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	store.rewrite = nil

	now = t0.Add(time.Minute)
	if err := m.Revoke(t.Context(), rec.ID); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(2 * time.Minute)
	if err := m.Revoke(t.Context(), rec.ID); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := m.Authenticate(t.Context(), key); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked key: err = %v", err)
	}
	if r, _ := store.MemoryStore.Lookup(t.Context(), rec.ID); !r.RevokedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("RevokedAt = %v, want the first revocation time", r.RevokedAt)
	}
	if err := m.Revoke(t.Context(), unknownID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking unknown id: err = %v", err)
	}
}

func TestStoreErrorIsNotUnauthenticated(t *testing.T) {
	now := t0
	m, store := newTestManager(t, &now)
	key, _, _ := m.Create(t.Context(), "u1", t0.Add(time.Hour))
	store.err = errors.New("db down")
	_, err := m.Authenticate(t.Context(), key)
	if err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("err = %v, want a non-authentication error", err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, p := range []string{"", "a", "1abc", "Abc", "ab_c", "ab-c", strings.Repeat("a", 17)} {
		if _, err := NewManager(p, NewMemoryStore()); err == nil {
			t.Errorf("NewManager(%q) succeeded", p)
		}
	}
	if _, err := NewManager("ok", nil); err == nil {
		t.Error("nil store accepted")
	}
	now := t0
	m, _ := newTestManager(t, &now)
	if _, _, err := m.Create(t.Context(), "", t0.Add(time.Hour)); err == nil {
		t.Error("empty subject accepted")
	}
	if _, _, err := m.Create(t.Context(), "u1", t0); err == nil {
		t.Error("expiry at now accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add("test_aaaqeayeaudaocaj_caireeyuculbogazdinryhi6d4qccirdeqssmjzifevcwlbnf32gdpqn")
	f.Add("test_aaaqeayeaudaocaj_caireeyuculbogazdinryhi6d4qccirdeqssmjzifevcwlbnf32gdpqa")
	f.Add("test__")
	f.Fuzz(func(t *testing.T, key string) {
		id, secret, ok := parse("test", key)
		if !ok {
			return
		}
		if got := format("test", id, secret); got != key {
			t.Fatalf("parse(%q) is not canonical: re-formats as %q", key, got)
		}
	})
}
