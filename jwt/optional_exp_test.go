package jwt

import (
	"errors"
	"testing"
	"time"
)

func TestOptionalExpiration(t *testing.T) {
	noExp := validClaims()
	noExp.ExpiresAt = NumericDate{}
	expired := validClaims()
	expired.ExpiresAt = NewNumericDate(testNow.Add(-time.Minute))
	for name, tc := range map[string]struct {
		claims Claims
		opts   []VerifierOption
		want   error
	}{
		"exp required by default":   {noExp, nil, ErrMissingClaim},
		"no exp accepted":           {noExp, []VerifierOption{WithOptionalExpiration()}, nil},
		"present exp still checked": {expired, []VerifierOption{WithOptionalExpiration()}, ErrExpired},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyClaims(t, tc.claims, tc.opts...); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	_, err := NewVerifier(NewStaticKeySet(), WithAlgorithms(ES256), WithAnyIssuer(), WithAnyAudience(),
		WithOptionalExpiration(), WithReplayCache(NewMemoryReplayCache()))
	if err == nil {
		t.Fatal("WithOptionalExpiration combined with WithReplayCache")
	}
}
