package totp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/tohshi/authent"
)

type recoveryStore struct {
	mu      sync.Mutex
	unused  map[string]map[RecoveryCodeHash]bool
	consume int
	err     error
}

func (s *recoveryStore) ConsumeRecoveryCode(_ context.Context, subject string, h RecoveryCodeHash) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consume++
	if s.err != nil {
		return s.err
	}
	if !s.unused[subject][h] {
		return ErrInvalidRecoveryCode
	}
	delete(s.unused[subject], h)
	return nil
}

func newRecovery(t *testing.T, n int) (*RecoveryAuthenticator, *recoveryStore, []string, []RecoveryCodeHash) {
	t.Helper()
	codes, hashes, err := GenerateRecoveryCodes(n)
	if err != nil {
		t.Fatal(err)
	}
	set := map[RecoveryCodeHash]bool{}
	for _, h := range hashes {
		set[h] = true
	}
	store := &recoveryStore{unused: map[string]map[RecoveryCodeHash]bool{"u1": set}}
	a, err := NewRecoveryAuthenticator(store)
	if err != nil {
		t.Fatal(err)
	}
	return a, store, codes, hashes
}

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, hashes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	format := regexp.MustCompile(`^[a-z2-7]{6}-[a-z2-7]{6}-[a-z2-7]{6}-[a-z2-7]{6}$`)
	seen := map[string]bool{}
	for i, c := range codes {
		if !format.MatchString(c) || seen[c] {
			t.Errorf("code %q is malformed or repeated", c)
		}
		seen[c] = true
		if hashes[i] != RecoveryCodeHash(sha256.Sum256([]byte(strings.ReplaceAll(c, "-", "")))) {
			t.Errorf("hash %d is not the SHA-256 of the code without hyphens", i)
		}
	}
	for _, n := range []int{0, -1, MaxRecoveryCodes + 1} {
		if _, _, err := GenerateRecoveryCodes(n); err == nil {
			t.Errorf("GenerateRecoveryCodes(%d) succeeded", n)
		}
	}
}

// The hash was computed with Python's hashlib.sha256 over the code
// without hyphens.
func TestRecoveryCodeHashVector(t *testing.T) {
	h, ok := parseRecoveryCode("ABCDEF-ghijkl mnopqr-stuvwx")
	want, _ := hex.DecodeString("93b0cabf8668e0c534c52a568957499e12a284f59d97dc9b2725ef836804875b")
	if !ok || hex.EncodeToString(h[:]) != hex.EncodeToString(want) {
		t.Fatalf("hash = %x, %v", h, ok)
	}
}

func TestRecoveryAuthenticate(t *testing.T) {
	ctx := context.Background()
	a, store, codes, _ := newRecovery(t, 3)

	p, err := a.Authenticate(ctx, "u1", codes[0])
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "u1" || p.Method != authent.MethodRecovery || p.AuthTime.IsZero() {
		t.Fatalf("unexpected principal %+v", p)
	}
	if _, err := a.Authenticate(ctx, "u1", codes[0]); !errors.Is(err, ErrInvalidRecoveryCode) || !errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("used code = %v, want ErrInvalidRecoveryCode", err)
	}
	loose := strings.ToUpper(strings.ReplaceAll(codes[1], "-", " "))
	if _, err := a.Authenticate(ctx, "u1", loose); err != nil {
		t.Fatalf("code typed in upper case with spaces = %v", err)
	}
	if _, err := a.Authenticate(ctx, "u2", codes[2]); !errors.Is(err, ErrInvalidRecoveryCode) {
		t.Fatalf("another subject's code = %v, want ErrInvalidRecoveryCode", err)
	}

	calls := store.consume
	for _, code := range []string{
		"",
		codes[2][:len(codes[2])-1],
		codes[2] + "a",
		strings.Replace(codes[2], "-", "_", 1),
		"0" + codes[2][1:],
		// U+212A KELVIN SIGN lower-cases to "k" in Unicode.
		"K" + codes[2][1:],
	} {
		if _, err := a.Authenticate(ctx, "u1", code); !errors.Is(err, ErrInvalidRecoveryCode) {
			t.Errorf("Authenticate(%q) = %v, want ErrInvalidRecoveryCode", code, err)
		}
	}
	if store.consume != calls {
		t.Fatalf("malformed codes caused %d store calls", store.consume-calls)
	}
	if _, err := a.Authenticate(ctx, "u1", codes[2]); err != nil {
		t.Fatalf("last unused code = %v", err)
	}
}

func TestRecoveryConcurrentUse(t *testing.T) {
	a, _, codes, _ := newRecovery(t, 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 16 {
		wg.Go(func() {
			if _, err := a.Authenticate(context.Background(), "u1", codes[0]); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d concurrent logins succeeded with one recovery code, want 1", ok)
	}
}

func TestRecoveryStoreError(t *testing.T) {
	a, store, codes, _ := newRecovery(t, 1)
	store.err = errors.New("db down")
	if _, err := a.Authenticate(context.Background(), "u1", codes[0]); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("store failure = %v, must not wrap ErrUnauthenticated", err)
	}
	if _, err := NewRecoveryAuthenticator(nil); err == nil {
		t.Fatal("nil store accepted")
	}
}
