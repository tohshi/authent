package totp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tohshi/authent"
)

var (
	// ErrInvalidCode is returned when a code is malformed or does not
	// match. It wraps authent.ErrUnauthenticated.
	ErrInvalidCode = fmt.Errorf("totp: invalid code: %w", authent.ErrUnauthenticated)
	// ErrReplay is returned when a code matches a time step that was
	// already used. It wraps ErrInvalidCode. Store.AdvanceCounter returns
	// it as well.
	ErrReplay = fmt.Errorf("%w: already used", ErrInvalidCode)
	// ErrNotEnrolled must be returned by Store.LookupCredential when the
	// subject has no TOTP key. It wraps authent.ErrUnauthenticated.
	ErrNotEnrolled = fmt.Errorf("totp: not enrolled: %w", authent.ErrUnauthenticated)
)

const (
	// DefaultSkew accepts the previous and the next time step, as RFC 6238
	// §5.2 recommends for clock drift and network delay.
	DefaultSkew = 1
	// MaxSkew is the largest accepted skew. Each extra step makes guessing
	// a code easier.
	MaxSkew = 5
)

// Credential is a subject's stored TOTP key.
type Credential struct {
	Subject string
	Key     Key
	// LastCounter is the latest time step that was used successfully.
	// Codes for this step and earlier ones are rejected.
	LastCounter uint64
}

// Store persists TOTP credentials. Implementations must be safe for
// concurrent use.
type Store interface {
	// LookupCredential returns ErrNotEnrolled if subject has no key.
	LookupCredential(ctx context.Context, subject string) (Credential, error)
	// AdvanceCounter sets the subject's LastCounter to counter if counter
	// is greater than the stored value, and returns ErrReplay otherwise.
	// The check and the update must be atomic (compare-and-set), so that
	// two concurrent logins cannot both use the same code.
	AdvanceCounter(ctx context.Context, subject string, counter uint64) error
}

// Authenticator verifies TOTP codes and rejects reused ones.
type Authenticator struct {
	store Store
	skew  uint
	now   func() time.Time
}

// AuthenticatorOption configures an Authenticator.
type AuthenticatorOption func(*Authenticator)

// WithSkew sets how many time steps before and after the current one are
// accepted. The default is DefaultSkew and the maximum is MaxSkew.
func WithSkew(steps uint) AuthenticatorOption { return func(a *Authenticator) { a.skew = steps } }

// WithClock overrides the clock, for tests.
func WithClock(now func() time.Time) AuthenticatorOption {
	return func(a *Authenticator) { a.now = now }
}

// NewAuthenticator returns an Authenticator backed by store.
func NewAuthenticator(store Store, opts ...AuthenticatorOption) (*Authenticator, error) {
	if store == nil {
		return nil, errors.New("totp: store is required")
	}
	a := &Authenticator{store: store, skew: DefaultSkew, now: time.Now}
	for _, opt := range opts {
		opt(a)
	}
	if a.skew > MaxSkew {
		return nil, fmt.Errorf("totp: skew larger than %d", MaxSkew)
	}
	return a, nil
}

// Authenticate verifies code for subject. It returns ErrInvalidCode (or
// ErrReplay, which wraps it) if the code is wrong or already used, and
// ErrNotEnrolled if the subject has no key. Other errors, such as store
// failures, do not wrap authent.ErrUnauthenticated.
func (a *Authenticator) Authenticate(ctx context.Context, subject, code string) (authent.Principal, error) {
	cred, err := a.store.LookupCredential(ctx, subject)
	switch {
	case errors.Is(err, ErrNotEnrolled):
		return authent.Principal{}, ErrNotEnrolled
	case err != nil:
		return authent.Principal{}, fmt.Errorf("totp: looking up credential: %w", err)
	}

	now := a.now()
	matches, err := cred.Key.matches(code, now, a.skew)
	switch {
	case errors.Is(err, errMalformedCode):
		return authent.Principal{}, fmt.Errorf("%w: %v", ErrInvalidCode, err)
	case err != nil:
		return authent.Principal{}, fmt.Errorf("totp: stored key for %q: %w", subject, err)
	case len(matches) == 0:
		return authent.Principal{}, ErrInvalidCode
	}

	// Use the earliest matching step that has not been used yet, so that a
	// code entered late is still accepted after an earlier login.
	counter, fresh := uint64(0), false
	for _, c := range matches {
		if c > cred.LastCounter {
			counter, fresh = c, true
			break
		}
	}
	if !fresh {
		return authent.Principal{}, ErrReplay
	}
	switch err := a.store.AdvanceCounter(ctx, subject, counter); {
	case errors.Is(err, ErrReplay):
		return authent.Principal{}, ErrReplay
	case err != nil:
		return authent.Principal{}, fmt.Errorf("totp: recording used code: %w", err)
	}

	return authent.Principal{
		Subject:  subject,
		Method:   authent.MethodTOTP,
		AuthTime: now,
	}, nil
}
