package jwt

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"
)

func verifyClaims(t *testing.T, c Claims, opts ...VerifierOption) error {
	t.Helper()
	s := ecSigner(t, "k")
	tok, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	_, err = newVerifier(t, NewStaticKeySet(s.VerificationKey()), opts...).Verify(context.Background(), tok)
	return err
}

func TestMaxTokenAge(t *testing.T) {
	issuedAgo := func(d time.Duration) Claims {
		c := validClaims()
		c.IssuedAt = NewNumericDate(testNow.Add(-d))
		return c
	}
	noIat := validClaims()
	noIat.IssuedAt = NumericDate{}
	for name, tc := range map[string]struct {
		claims Claims
		leeway time.Duration
		want   error
	}{
		"fresh":                 {issuedAgo(time.Minute), 0, nil},
		"at the limit":          {issuedAgo(10 * time.Minute), 0, nil},
		"past the limit":        {issuedAgo(10*time.Minute + time.Second), 0, ErrTokenTooOld},
		"within leeway":         {issuedAgo(10*time.Minute + 30*time.Second), 30 * time.Second, nil},
		"past limit and leeway": {issuedAgo(10*time.Minute + 31*time.Second), 30 * time.Second, ErrTokenTooOld},
		"no iat":                {noIat, 0, ErrMissingClaim},
	} {
		t.Run(name, func(t *testing.T) {
			err := verifyClaims(t, tc.claims, WithMaxTokenAge(10*time.Minute), WithLeeway(tc.leeway))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if err := verifyClaims(t, noIat); err != nil {
		t.Fatalf("iat required without WithMaxTokenAge: %v", err)
	}
}

func TestMaxAuthAge(t *testing.T) {
	authAgo := func(d time.Duration) Claims {
		c := validClaims()
		c.Extra = map[string]any{"auth_time": testNow.Add(-d).Unix()}
		return c
	}
	withAuthTime := func(v any) Claims {
		c := validClaims()
		c.Extra = map[string]any{"auth_time": v}
		return c
	}
	for name, tc := range map[string]struct {
		claims Claims
		max    time.Duration
		leeway time.Duration
		want   error
	}{
		"recent":                {authAgo(time.Minute), time.Hour, 0, nil},
		"at the limit":          {authAgo(time.Hour), time.Hour, 0, nil},
		"past the limit":        {authAgo(time.Hour + time.Second), time.Hour, 0, ErrAuthenticationTooOld},
		"within leeway":         {authAgo(time.Hour + 30*time.Second), time.Hour, 30 * time.Second, nil},
		"past limit and leeway": {authAgo(time.Hour + 31*time.Second), time.Hour, 30 * time.Second, ErrAuthenticationTooOld},
		"zero, just now":        {authAgo(0), 0, 0, nil},
		"zero, a second ago":    {authAgo(time.Second), 0, 0, ErrAuthenticationTooOld},
		"no auth_time":          {validClaims(), time.Hour, 0, ErrMissingClaim},
		"string auth_time":      {withAuthTime("1700000000"), time.Hour, 0, ErrMalformed},
		"negative auth_time":    {withAuthTime(-1), time.Hour, 0, ErrMalformed},
		"huge auth_time":        {withAuthTime(1e300), time.Hour, 0, ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			err := verifyClaims(t, tc.claims, WithMaxAuthAge(tc.max), WithLeeway(tc.leeway))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if err := verifyClaims(t, validClaims()); err != nil {
		t.Fatalf("auth_time required without WithMaxAuthAge: %v", err)
	}
}

func TestClaimsAuthTime(t *testing.T) {
	var c Claims
	if err := json.Unmarshal([]byte(`{"auth_time":1700000000}`), &c); err != nil {
		t.Fatal(err)
	}
	at, err := c.AuthTime()
	if err != nil || !at.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("AuthTime = %v, %v", at, err)
	}
	if at, err := (Claims{}).AuthTime(); err != nil || !at.IsZero() {
		t.Fatalf("absent auth_time = %v, %v", at, err)
	}
}

func TestNegativeMaxAgeRejected(t *testing.T) {
	for _, opt := range []VerifierOption{WithMaxTokenAge(-time.Second), WithMaxAuthAge(-time.Second)} {
		if _, err := NewVerifier(NewStaticKeySet(), WithAlgorithms(ES256), WithAnyIssuer(), WithAnyAudience(), opt); err == nil {
			t.Fatal("negative maximum age accepted")
		}
	}
}
