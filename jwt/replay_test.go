package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

func TestMemoryReplayCacheExpiry(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryReplayCache()
	now := testNow
	c.now = func() time.Time { return now }
	if ok, _ := c.Add(ctx, "a", time.Minute); !ok {
		t.Fatal("first Add")
	}
	if ok, _ := c.Add(ctx, "a", time.Minute); ok {
		t.Fatal("duplicate accepted")
	}
	now = now.Add(2 * time.Minute)
	if ok, _ := c.Add(ctx, "a", time.Minute); !ok {
		t.Fatal("expired entry still blocks")
	}
	if len(c.seen) != 1 {
		t.Fatalf("expired entries not swept: %d", len(c.seen))
	}
}

// recordingCache wraps a MemoryReplayCache and records each TTL it is
// given.
type recordingCache struct {
	*MemoryReplayCache
	mu   sync.Mutex
	ttls []time.Duration
}

func (c *recordingCache) Add(ctx context.Context, id string, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	c.ttls = append(c.ttls, ttl)
	c.mu.Unlock()
	return c.MemoryReplayCache.Add(ctx, id, ttl)
}

func claimsWithID(jti string) Claims {
	c := validClaims()
	c.ID = jti
	return c
}

func TestReplayCacheRejectsReplays(t *testing.T) {
	ctx := context.Background()
	cache := &recordingCache{MemoryReplayCache: NewMemoryReplayCache()}
	v := newVerifier(t, NewStaticKeySet(ecSigner(t, "k").VerificationKey()),
		WithReplayCache(cache), WithLeeway(30*time.Second))
	tok, err := ecSigner(t, "k").Sign(claimsWithID("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(ctx, tok)
	if !errors.Is(err, ErrReplayed) || !errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("replay: err = %v", err)
	}
	// The entry lives until exp plus the leeway, when the token stops
	// being accepted anyway.
	if want := time.Hour + 30*time.Second; len(cache.ttls) == 0 || cache.ttls[0] != want {
		t.Fatalf("ttl = %v, want %v", cache.ttls, want)
	}
}

func TestReplayCacheRequiresJTI(t *testing.T) {
	ks := NewStaticKeySet(ecSigner(t, "k").VerificationKey())
	tok, _ := ecSigner(t, "k").Sign(validClaims())
	if _, err := newVerifier(t, ks).Verify(context.Background(), tok); err != nil {
		t.Fatalf("without the option: %v", err)
	}
	_, err := newVerifier(t, ks, WithReplayCache(NewMemoryReplayCache())).Verify(context.Background(), tok)
	if !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("err = %v, want ErrMissingClaim", err)
	}
}

func TestReplayCacheScopesJTIByIssuer(t *testing.T) {
	ctx := context.Background()
	v := newVerifier(t, NewStaticKeySet(ecSigner(t, "k").VerificationKey()),
		WithIssuer("https://other.example"), WithReplayCache(NewMemoryReplayCache()))
	for _, iss := range []string{testIssuer, "https://other.example"} {
		c := claimsWithID("same")
		c.Issuer = iss
		tok, _ := ecSigner(t, "k").Sign(c)
		if _, err := v.Verify(ctx, tok); err != nil {
			t.Fatalf("iss %s: %v", iss, err)
		}
	}
}

// A token that fails any other check must not burn its jti: the valid
// token with the same jti is still accepted afterwards.
func TestReplayRecordedOnlyAfterAllChecks(t *testing.T) {
	ctx := context.Background()
	signer := ecSigner(t, "k")
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := NewSigner(ES256, otherKey, WithKeyID("k"))
	wrongAud := claimsWithID("j")
	wrongAud.Audience = Audience{"elsewhere"}
	expired := claimsWithID("j")
	expired.ExpiresAt = NewNumericDate(testNow.Add(-time.Hour))
	noSub := claimsWithID("j")
	noSub.Subject = ""

	tok := func(s *Signer, c Claims) string {
		out, err := s.Sign(c)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	v := newVerifier(t, NewStaticKeySet(signer.VerificationKey()), WithReplayCache(NewMemoryReplayCache()))
	for name, bad := range map[string]string{
		"bad signature": tok(other, claimsWithID("j")),
		"wrong aud":     tok(signer, wrongAud),
		"expired":       tok(signer, expired),
	} {
		if _, err := v.Verify(ctx, bad); err == nil || errors.Is(err, ErrReplayed) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if _, err := v.Authenticate(ctx, tok(signer, noSub)); !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("no sub: err = %v", err)
	}
	if _, err := v.Authenticate(ctx, tok(signer, claimsWithID("j"))); err != nil {
		t.Fatalf("valid token after rejected ones: %v", err)
	}
}

type failingReplayCache struct{}

func (failingReplayCache) Add(context.Context, string, time.Duration) (bool, error) {
	return false, errors.New("store down")
}

func TestReplayCacheFailureFailsClosed(t *testing.T) {
	v := newVerifier(t, NewStaticKeySet(ecSigner(t, "k").VerificationKey()), WithReplayCache(failingReplayCache{}))
	tok, _ := ecSigner(t, "k").Sign(claimsWithID("j"))
	c, err := v.Verify(context.Background(), tok)
	if err == nil || c != nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("claims %v, err = %v, want an infrastructure error", c, err)
	}
}

func TestReplayCacheConcurrentVerification(t *testing.T) {
	v := newVerifier(t, NewStaticKeySet(ecSigner(t, "k").VerificationKey()), WithReplayCache(NewMemoryReplayCache()))
	tok, _ := ecSigner(t, "k").Sign(claimsWithID("once"))
	var ok, replayed atomic.Int32
	var wg sync.WaitGroup
	const n = 32
	for range n {
		wg.Go(func() {
			_, err := v.Verify(context.Background(), tok)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrReplayed):
				replayed.Add(1)
			default:
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 1 || replayed.Load() != n-1 {
		t.Fatalf("%d accepted, %d replayed; want exactly one accepted", ok.Load(), replayed.Load())
	}
}
