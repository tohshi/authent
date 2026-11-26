package totp

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/tohshi/authent"
)

// rfc4226 are the HOTP values for counters 0 to 9 from RFC 4226
// Appendix D.
var rfc4226 = []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}

func rfc4226Key() Key {
	return Key{Secret: []byte("12345678901234567890"), Algorithm: SHA1, Digits: 6}
}

type hotpStore struct {
	mu    sync.Mutex
	creds map[string]HOTPCredential
	err   error
}

func (s *hotpStore) LookupHOTPCredential(_ context.Context, subject string) (HOTPCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return HOTPCredential{}, s.err
	}
	c, ok := s.creds[subject]
	if !ok {
		return HOTPCredential{}, ErrNotEnrolled
	}
	return c, nil
}

func (s *hotpStore) AdvanceHOTPCounter(_ context.Context, subject string, first, next uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.creds[subject]
	if first < c.Counter {
		return ErrReplay
	}
	c.Counter = next
	s.creds[subject] = c
	return nil
}

func (s *hotpStore) counter(subject string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.creds[subject].Counter
}

func newHOTP(t *testing.T, counter uint64, opts ...HOTPOption) (*HOTPAuthenticator, *hotpStore) {
	t.Helper()
	store := &hotpStore{creds: map[string]HOTPCredential{"u1": {Subject: "u1", Key: rfc4226Key(), Counter: counter}}}
	a, err := NewHOTPAuthenticator(store, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return a, store
}

func TestHOTPAuthenticate(t *testing.T) {
	ctx := context.Background()
	a, store := newHOTP(t, 0)

	p, err := a.Authenticate(ctx, "u1", rfc4226[0])
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "u1" || p.Method != authent.MethodHOTP || p.AuthTime.IsZero() {
		t.Fatalf("unexpected principal %+v", p)
	}
	if store.counter("u1") != 1 {
		t.Fatalf("counter = %d, want 1", store.counter("u1"))
	}
	if _, err := a.Authenticate(ctx, "u1", rfc4226[0]); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("reused code = %v, want ErrInvalidCode", err)
	}

	if _, err := a.Authenticate(ctx, "u1", rfc4226[5]); err != nil {
		t.Fatalf("code within the look-ahead window = %v", err)
	}
	if store.counter("u1") != 6 {
		t.Fatalf("counter = %d, want 6", store.counter("u1"))
	}
	if _, err := a.Authenticate(ctx, "u1", rfc4226[3]); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("skipped earlier code = %v, want ErrInvalidCode", err)
	}

	for _, code := range []string{"", "75522", "7552240", "75522a", "７５５２２４"} {
		if _, err := a.Authenticate(ctx, "u1", code); !errors.Is(err, ErrInvalidCode) || !errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("Authenticate(%q) = %v, want ErrInvalidCode", code, err)
		}
	}
	if _, err := a.Authenticate(ctx, "u2", rfc4226[6]); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("unknown subject = %v, want ErrNotEnrolled", err)
	}
}

func TestHOTPLookAheadWindow(t *testing.T) {
	ctx := context.Background()
	a, _ := newHOTP(t, 0, WithLookAhead(3))
	if _, err := a.Authenticate(ctx, "u1", rfc4226[3]); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("code just past the window = %v, want ErrInvalidCode", err)
	}
	if _, err := a.Authenticate(ctx, "u1", rfc4226[2]); err != nil {
		t.Fatalf("last code in the window = %v", err)
	}
}

func TestHOTPResync(t *testing.T) {
	ctx := context.Background()
	a, store := newHOTP(t, 0, WithLookAhead(3), WithResyncWindow(8))

	if _, err := a.Authenticate(ctx, "u1", rfc4226[7]); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("code past the window = %v, want ErrInvalidCode", err)
	}
	for name, pair := range map[string][2]string{
		"not consecutive":    {rfc4226[7], rfc4226[9]},
		"reversed":           {rfc4226[8], rfc4226[7]},
		"starts past window": {rfc4226[8], rfc4226[9]},
		"malformed second":   {rfc4226[7], "abcdef"},
	} {
		if _, err := a.Resync(ctx, "u1", pair[0], pair[1]); !errors.Is(err, ErrInvalidCode) {
			t.Errorf("%s: Resync(%q, %q) = %v, want ErrInvalidCode", name, pair[0], pair[1], err)
		}
	}
	if store.counter("u1") != 0 {
		t.Fatalf("failed resyncs moved the counter to %d", store.counter("u1"))
	}
	p, err := a.Resync(ctx, "u1", rfc4226[7], rfc4226[8])
	if err != nil || p.Method != authent.MethodHOTP {
		t.Fatalf("Resync = %+v, %v", p, err)
	}
	if store.counter("u1") != 9 {
		t.Fatalf("counter = %d, want 9", store.counter("u1"))
	}
	if _, err := a.Authenticate(ctx, "u1", rfc4226[9]); err != nil {
		t.Fatalf("code after resync = %v", err)
	}
}

func TestHOTPConcurrentReplay(t *testing.T) {
	a, _ := newHOTP(t, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 16 {
		wg.Go(func() {
			if _, err := a.Authenticate(context.Background(), "u1", rfc4226[0]); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d concurrent logins succeeded with one code, want 1", ok)
	}
}

// staleHOTPStore returns the credential as it was when the store was
// wrapped, as if the lookup ran before a concurrent login advanced it.
type staleHOTPStore struct {
	*hotpStore
	snapshot HOTPCredential
}

func (s staleHOTPStore) LookupHOTPCredential(context.Context, string) (HOTPCredential, error) {
	return s.snapshot, nil
}

func TestHOTPResyncStaleLookup(t *testing.T) {
	ctx := context.Background()
	a, store := newHOTP(t, 0)
	stale, err := NewHOTPAuthenticator(staleHOTPStore{store, store.creds["u1"]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(ctx, "u1", rfc4226[3]); err != nil {
		t.Fatal(err)
	}
	if _, err := stale.Resync(ctx, "u1", rfc4226[3], rfc4226[4]); !errors.Is(err, ErrReplay) {
		t.Fatalf("Resync with a used first code = %v, want ErrReplay", err)
	}
	if _, err := stale.Authenticate(ctx, "u1", rfc4226[2]); !errors.Is(err, ErrReplay) {
		t.Fatalf("Authenticate with a skipped code = %v, want ErrReplay", err)
	}
	if store.counter("u1") != 4 {
		t.Fatalf("counter = %d, want 4", store.counter("u1"))
	}
	if _, err := stale.Resync(ctx, "u1", rfc4226[4], rfc4226[5]); err != nil {
		t.Fatalf("Resync with unused codes = %v", err)
	}
}

func TestHOTPConcurrentAuthenticateAndResync(t *testing.T) {
	for range 50 {
		a, _ := newHOTP(t, 0)
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for i := range 32 {
			wg.Go(func() {
				var err error
				if i%2 == 0 {
					_, err = a.Authenticate(context.Background(), "u1", rfc4226[3])
				} else {
					_, err = a.Resync(context.Background(), "u1", rfc4226[3], rfc4226[4])
				}
				if err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if ok != 1 {
			t.Fatalf("%d logins succeeded with one code, want 1", ok)
		}
	}
}

func TestHOTPCounterLimit(t *testing.T) {
	ctx := context.Background()
	a, store := newHOTP(t, math.MaxUint64)
	k := rfc4226Key()
	if _, err := a.Authenticate(ctx, "u1", k.hotp(math.MaxUint64)); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("code at the last counter value = %v, want ErrInvalidCode", err)
	}
	store.creds["u1"] = HOTPCredential{Subject: "u1", Key: k, Counter: math.MaxUint64 - 1}
	if _, err := a.Authenticate(ctx, "u1", k.hotp(math.MaxUint64-1)); err != nil {
		t.Fatalf("code before the last counter value = %v", err)
	}
	if store.counter("u1") != math.MaxUint64 {
		t.Fatalf("counter = %d", store.counter("u1"))
	}
}

func TestHOTPErrors(t *testing.T) {
	ctx := context.Background()
	a, store := newHOTP(t, 0)
	store.err = errors.New("db down")
	if _, err := a.Authenticate(ctx, "u1", rfc4226[0]); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("store failure = %v, must not wrap ErrUnauthenticated", err)
	}
	store.err = nil
	store.creds["u1"] = HOTPCredential{Subject: "u1", Key: Key{Secret: []byte("short"), Algorithm: SHA1, Digits: 6}}
	if _, err := a.Authenticate(ctx, "u1", rfc4226[0]); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("invalid stored key = %v, must not wrap ErrUnauthenticated", err)
	}

	if _, err := NewHOTPAuthenticator(nil); err == nil {
		t.Fatal("nil store accepted")
	}
	for _, opt := range []HOTPOption{WithLookAhead(0), WithLookAhead(MaxLookAhead + 1), WithResyncWindow(1), WithResyncWindow(MaxResyncWindow + 1)} {
		if _, err := NewHOTPAuthenticator(store, opt); err == nil {
			t.Error("invalid option accepted")
		}
	}
}

func TestHOTPURI(t *testing.T) {
	got, err := rfc4226Key().HOTPURI("ACME Co", "john", 5)
	if err != nil {
		t.Fatal(err)
	}
	want := "otpauth://hotp/ACME%20Co:john?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&algorithm=SHA1&digits=6&counter=5"
	if got != want {
		t.Fatalf("HOTPURI =\n%s\nwant\n%s", got, want)
	}
}
