package totp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observe"
)

// ErrInvalidRecoveryCode is returned when a recovery code is malformed,
// unknown or already used. It wraps authent.ErrUnauthenticated.
// RecoveryStore.ConsumeRecoveryCode returns it as well.
var ErrInvalidRecoveryCode = fmt.Errorf("totp: invalid recovery code: %w", authent.ErrUnauthenticated)

// MaxRecoveryCodes is the most codes GenerateRecoveryCodes returns at once.
const MaxRecoveryCodes = 100

const (
	recoveryBytes = 15
	recoveryLen   = recoveryBytes * 8 / 5
	recoveryGroup = 6
)

var recoveryEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// RecoveryCodeHash is the stored form of a recovery code.
type RecoveryCodeHash [sha256.Size]byte

// GenerateRecoveryCodes returns n single-use recovery codes to show to the
// user once, and their hashes to store. Each code carries 120 random bits,
// enough for a plain SHA-256 to resist offline guessing (NIST SP 800-63B
// §5.1.2.1 requires 112), and looks like "abcdef-ghijkl-mnopqr-stuvwx".
func GenerateRecoveryCodes(n int) ([]string, []RecoveryCodeHash, error) {
	if n < 1 || n > MaxRecoveryCodes {
		return nil, nil, fmt.Errorf("totp: number of recovery codes must be between 1 and %d", MaxRecoveryCodes)
	}
	codes := make([]string, n)
	hashes := make([]RecoveryCodeHash, n)
	raw := make([]byte, recoveryBytes)
	for i := range codes {
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, err
		}
		canonical := recoveryEncoding.EncodeToString(raw)
		groups := make([]string, 0, recoveryLen/recoveryGroup)
		for j := 0; j < recoveryLen; j += recoveryGroup {
			groups = append(groups, canonical[j:j+recoveryGroup])
		}
		codes[i] = strings.Join(groups, "-")
		hashes[i] = sha256.Sum256([]byte(canonical))
	}
	return codes, hashes, nil
}

func parseRecoveryCode(code string) (RecoveryCodeHash, bool) {
	b := make([]byte, 0, recoveryLen)
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c == '-' || c == ' ':
			continue
		case 'A' <= c && c <= 'Z':
			c += 'a' - 'A'
		case !('a' <= c && c <= 'z' || '2' <= c && c <= '7'):
			return RecoveryCodeHash{}, false
		}
		b = append(b, c)
	}
	if len(b) != recoveryLen {
		return RecoveryCodeHash{}, false
	}
	return sha256.Sum256(b), true
}

// RecoveryStore persists the hashes of unused recovery codes.
// Implementations must be safe for concurrent use.
type RecoveryStore interface {
	// ConsumeRecoveryCode removes hash from the subject's unused recovery
	// codes and returns ErrInvalidRecoveryCode if it is not among them.
	// The check and the removal must be atomic, so that two concurrent
	// logins cannot both use the same code.
	ConsumeRecoveryCode(ctx context.Context, subject string, hash RecoveryCodeHash) error
}

// RecoveryAuthenticator verifies single-use recovery codes, the fallback
// for a lost second factor.
type RecoveryAuthenticator struct {
	store    RecoveryStore
	observer authent.Observer
}

// RecoveryOption configures a RecoveryAuthenticator.
type RecoveryOption func(*RecoveryAuthenticator)

// WithRecoveryObserver sends an Event for every Authenticate call to o.
func WithRecoveryObserver(o authent.Observer) RecoveryOption {
	return func(a *RecoveryAuthenticator) { a.observer = o }
}

// NewRecoveryAuthenticator returns a RecoveryAuthenticator backed by store.
func NewRecoveryAuthenticator(store RecoveryStore, opts ...RecoveryOption) (*RecoveryAuthenticator, error) {
	if store == nil {
		return nil, errors.New("totp: store is required")
	}
	a := &RecoveryAuthenticator{store: store}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Authenticate consumes code for subject. It returns
// ErrInvalidRecoveryCode if the code is malformed, unknown or already used.
// Malformed codes do not reach the store. Other errors, such as store
// failures, do not wrap authent.ErrUnauthenticated.
func (a *RecoveryAuthenticator) Authenticate(ctx context.Context, subject, code string) (authent.Principal, error) {
	start := observe.Start(a.observer)
	p, err := a.authenticate(ctx, subject, code)
	observe.Done(ctx, a.observer, authent.KindAuthentication, authent.MethodRecovery, start, p.Subject, err)
	return p, err
}

func (a *RecoveryAuthenticator) authenticate(ctx context.Context, subject, code string) (authent.Principal, error) {
	h, ok := parseRecoveryCode(code)
	if !ok {
		return authent.Principal{}, ErrInvalidRecoveryCode
	}
	switch err := a.store.ConsumeRecoveryCode(ctx, subject, h); {
	case errors.Is(err, ErrInvalidRecoveryCode):
		return authent.Principal{}, ErrInvalidRecoveryCode
	case err != nil:
		return authent.Principal{}, fmt.Errorf("totp: consuming recovery code: %w", err)
	}
	return authent.Principal{
		Subject:  subject,
		Method:   authent.MethodRecovery,
		AuthTime: time.Now(),
	}, nil
}
