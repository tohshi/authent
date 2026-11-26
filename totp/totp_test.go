package totp

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

// RFC 4226 Appendix D.
func TestHOTPVectors(t *testing.T) {
	k := Key{Secret: []byte("12345678901234567890"), Algorithm: SHA1, Digits: 6, Period: 30 * time.Second}
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := k.hotp(uint64(i)); got != w {
			t.Errorf("HOTP(%d) = %s, want %s", i, got, w)
		}
	}
}

// RFC 6238 Appendix B.
func TestTOTPVectors(t *testing.T) {
	keys := map[Algorithm][]byte{
		SHA1:   []byte("12345678901234567890"),
		SHA256: []byte("12345678901234567890123456789012"),
		SHA512: []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}
	for _, tc := range []struct {
		unix int64
		want map[Algorithm]string
	}{
		{59, map[Algorithm]string{SHA1: "94287082", SHA256: "46119246", SHA512: "90693936"}},
		{1111111109, map[Algorithm]string{SHA1: "07081804", SHA256: "68084774", SHA512: "25091201"}},
		{1111111111, map[Algorithm]string{SHA1: "14050471", SHA256: "67062674", SHA512: "99943326"}},
		{1234567890, map[Algorithm]string{SHA1: "89005924", SHA256: "91819424", SHA512: "93441116"}},
		{2000000000, map[Algorithm]string{SHA1: "69279037", SHA256: "90698825", SHA512: "38618901"}},
		{20000000000, map[Algorithm]string{SHA1: "65353130", SHA256: "77737706", SHA512: "47863826"}},
	} {
		for alg, want := range tc.want {
			k := Key{Secret: keys[alg], Algorithm: alg, Digits: 8, Period: 30 * time.Second}
			got, err := k.Code(time.Unix(tc.unix, 0))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%s at %d = %s, want %s", alg, tc.unix, got, want)
			}
		}
	}
}

func TestGenerateKey(t *testing.T) {
	for alg, size := range map[Algorithm]int{SHA1: 20, SHA256: 32, SHA512: 64} {
		k, err := GenerateKey(WithAlgorithm(alg), WithDigits(8), WithPeriod(60*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if len(k.Secret) != size || k.Digits != 8 || k.Period != time.Minute || k.Algorithm != alg {
			t.Errorf("GenerateKey(%s) = %+v", alg, k)
		}
	}
	a, _ := GenerateKey()
	b, _ := GenerateKey()
	if string(a.Secret) == string(b.Secret) {
		t.Fatal("secrets are not random")
	}
	if a.Algorithm != SHA1 || a.Digits != 6 || a.Period != 30*time.Second {
		t.Fatalf("unexpected defaults %+v", a)
	}
	for _, opt := range []KeyOption{WithAlgorithm("MD5"), WithDigits(5), WithDigits(9), WithPeriod(0), WithPeriod(1500 * time.Millisecond)} {
		if _, err := GenerateKey(opt); err == nil {
			t.Error("GenerateKey accepted an invalid option")
		}
	}
}

func TestValidateRejectsShortSecret(t *testing.T) {
	k := Key{Secret: make([]byte, MinSecretLength-1), Algorithm: SHA1, Digits: 6, Period: 30 * time.Second}
	if k.Validate() == nil {
		t.Fatal("short secret accepted")
	}
	if _, err := k.Code(time.Now()); err == nil {
		t.Fatal("Code accepted a short secret")
	}
}

func TestURI(t *testing.T) {
	k := Key{Secret: []byte("12345678901234567890"), Algorithm: SHA1, Digits: 6, Period: 30 * time.Second}
	got, err := k.URI("ACME Co", "john.doe@example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := "otpauth://totp/ACME%20Co:john.doe@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
	if got != want {
		t.Fatalf("URI =\n%s\nwant\n%s", got, want)
	}
	u, err := url.Parse(got)
	if err != nil || u.Query().Get("issuer") != "ACME Co" {
		t.Fatalf("URI does not round-trip: %v", err)
	}

	got, _ = k.URI("", "bob")
	if got != "otpauth://totp/bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30" {
		t.Fatalf("URI without issuer = %s", got)
	}

	for _, tc := range [][2]string{{"a:b", "c"}, {"a", "b:c"}, {"a", ""}, {"a", " b"}} {
		if _, err := k.URI(tc[0], tc[1]); err == nil {
			t.Errorf("URI(%q, %q) accepted", tc[0], tc[1])
		}
	}
}

func TestVerify(t *testing.T) {
	k := Key{Secret: []byte("12345678901234567890"), Algorithm: SHA1, Digits: 8, Period: 30 * time.Second}
	at := time.Unix(59, 0) // counter 1, code 94287082
	if c, err := k.Verify("94287082", at, 0); err != nil || c != 1 {
		t.Fatalf("Verify = %d, %v", c, err)
	}
	// One step later the code is only accepted with skew.
	later := at.Add(30 * time.Second)
	if _, err := k.Verify("94287082", later, 0); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Verify without skew = %v", err)
	}
	if c, err := k.Verify("94287082", later, 1); err != nil || c != 1 {
		t.Fatalf("Verify with skew = %d, %v", c, err)
	}
	// The skew window does not underflow at the epoch.
	if c, err := k.Verify("94287082", time.Unix(0, 0), 1); err != nil || c != 1 {
		t.Fatalf("Verify near the epoch = %d, %v", c, err)
	}

	for _, code := range []string{"", "9428708", "942870820", "9428708a", " 94287082", "９４２８７０８２"} {
		_, err := k.Verify(code, at, 1)
		if !errors.Is(err, ErrInvalidCode) || !errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("Verify(%q) = %v, want ErrInvalidCode", code, err)
		}
	}
	if _, err := k.Verify("94287082", at, MaxSkew+1); err == nil {
		t.Fatal("excessive skew accepted")
	}
	if _, err := k.Verify("94287082", time.Unix(-1, 0), 1); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("pre-epoch time = %v", err)
	}
}

type fakeStore struct {
	mu    sync.Mutex
	creds map[string]Credential
	err   error
}

func (s *fakeStore) LookupCredential(_ context.Context, subject string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return Credential{}, s.err
	}
	c, ok := s.creds[subject]
	if !ok {
		return Credential{}, ErrNotEnrolled
	}
	return c, nil
}

func (s *fakeStore) AdvanceCounter(_ context.Context, subject string, counter uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.creds[subject]
	if counter <= c.LastCounter {
		return ErrReplay
	}
	c.LastCounter = counter
	s.creds[subject] = c
	return nil
}

func TestAuthenticate(t *testing.T) {
	k, _ := GenerateKey()
	store := &fakeStore{creds: map[string]Credential{"u-1": {Subject: "u-1", Key: k}}}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	a, err := NewAuthenticator(store, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	code, _ := k.Code(now)
	p, err := a.Authenticate(ctx, "u-1", code)
	if err != nil {
		t.Fatalf("Authenticate = %v", err)
	}
	if p.Subject != "u-1" || p.Method != authent.MethodTOTP || !p.AuthTime.Equal(now) {
		t.Fatalf("unexpected principal %+v", p)
	}

	// The same code cannot be used twice.
	if _, err := a.Authenticate(ctx, "u-1", code); !errors.Is(err, ErrReplay) || !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replayed code = %v, want ErrReplay", err)
	}
	// Neither can a code from an earlier step.
	prev, _ := k.Code(now.Add(-30 * time.Second))
	if _, err := a.Authenticate(ctx, "u-1", prev); !errors.Is(err, ErrReplay) {
		t.Fatalf("earlier code = %v, want ErrReplay", err)
	}
	// The next step's code is accepted within the skew.
	next, _ := k.Code(now.Add(30 * time.Second))
	if _, err := a.Authenticate(ctx, "u-1", next); err != nil {
		t.Fatalf("next code = %v", err)
	}
	// Codes outside the skew are rejected.
	far, _ := k.Code(now.Add(-90 * time.Second))
	if _, err := a.Authenticate(ctx, "u-1", far); !errors.Is(err, ErrInvalidCode) || errors.Is(err, ErrReplay) {
		t.Fatalf("far code = %v, want ErrInvalidCode", err)
	}

	if _, err := a.Authenticate(ctx, "u-2", code); !errors.Is(err, ErrNotEnrolled) || !errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("unknown subject = %v, want ErrNotEnrolled", err)
	}
	if _, err := a.Authenticate(ctx, "u-1", "abc"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("malformed code = %v", err)
	}
}

func TestAuthenticateConcurrentReplay(t *testing.T) {
	k, _ := GenerateKey()
	store := &fakeStore{creds: map[string]Credential{"u-1": {Subject: "u-1", Key: k}}}
	now := time.Now()
	a, _ := NewAuthenticator(store, WithClock(func() time.Time { return now }))
	code, _ := k.Code(now)

	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 16 {
		wg.Go(func() {
			if _, err := a.Authenticate(context.Background(), "u-1", code); err == nil {
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

func TestAuthenticateInfrastructureErrors(t *testing.T) {
	ctx := context.Background()
	store := &fakeStore{err: errors.New("db down")}
	a, _ := NewAuthenticator(store)
	if _, err := a.Authenticate(ctx, "u-1", "123456"); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("store failure = %v, must not wrap ErrUnauthenticated", err)
	}

	bad := &fakeStore{creds: map[string]Credential{"u-1": {Subject: "u-1", Key: Key{Secret: []byte("short")}}}}
	a, _ = NewAuthenticator(bad)
	if _, err := a.Authenticate(ctx, "u-1", "123456"); err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("invalid stored key = %v, must not wrap ErrUnauthenticated", err)
	}
}

func TestNewAuthenticatorOptions(t *testing.T) {
	if _, err := NewAuthenticator(nil); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := NewAuthenticator(&fakeStore{}, WithSkew(MaxSkew+1)); err == nil || !strings.Contains(err.Error(), "skew") {
		t.Fatalf("excessive skew = %v", err)
	}
}
