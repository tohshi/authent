package totp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/tohshi/authent"
)

const (
	// DefaultLookAhead is how many counter values, starting at the expected
	// one, HOTPAuthenticator.Authenticate accepts (RFC 4226 §7.4).
	DefaultLookAhead = 10
	// MaxLookAhead is the largest accepted look-ahead window. Each extra
	// value makes guessing a code easier.
	MaxLookAhead = 50
	// DefaultResyncWindow is how many counter values, starting at the
	// expected one, Resync searches for the first of two consecutive codes.
	DefaultResyncWindow = 1000
	// MaxResyncWindow is the largest accepted resynchronization window.
	MaxResyncWindow = 10000
)

// HOTPCredential is a subject's stored counter-based (HOTP) key.
type HOTPCredential struct {
	Subject string
	// Key.Period is not used.
	Key Key
	// Counter is the counter value of the next code the token is expected
	// to show. Codes for earlier values are rejected.
	Counter uint64
}

// HOTPStore persists HOTP credentials. Implementations must be safe for
// concurrent use.
type HOTPStore interface {
	// LookupHOTPCredential returns ErrNotEnrolled if subject has no key.
	LookupHOTPCredential(ctx context.Context, subject string) (HOTPCredential, error)
	// AdvanceHOTPCounter sets the subject's Counter to counter if counter
	// is greater than the stored value, and returns ErrReplay otherwise.
	// The check and the update must be atomic (compare-and-set), so that
	// two concurrent logins cannot both use the same code.
	AdvanceHOTPCounter(ctx context.Context, subject string, counter uint64) error
}

// HOTPAuthenticator verifies counter-based codes (RFC 4226).
type HOTPAuthenticator struct {
	store     HOTPStore
	lookAhead uint
	resync    uint
}

// HOTPOption configures a HOTPAuthenticator.
type HOTPOption func(*HOTPAuthenticator)

// WithLookAhead sets how many counter values, starting at the expected
// one, are accepted. The default is DefaultLookAhead and the maximum is
// MaxLookAhead.
func WithLookAhead(n uint) HOTPOption { return func(a *HOTPAuthenticator) { a.lookAhead = n } }

// WithResyncWindow sets how many counter values Resync searches for the
// first code. The default is DefaultResyncWindow and the maximum is MaxResyncWindow.
func WithResyncWindow(n uint) HOTPOption { return func(a *HOTPAuthenticator) { a.resync = n } }

// NewHOTPAuthenticator returns a HOTPAuthenticator backed by store.
func NewHOTPAuthenticator(store HOTPStore, opts ...HOTPOption) (*HOTPAuthenticator, error) {
	if store == nil {
		return nil, errors.New("totp: store is required")
	}
	a := &HOTPAuthenticator{store: store, lookAhead: DefaultLookAhead, resync: DefaultResyncWindow}
	for _, opt := range opts {
		opt(a)
	}
	switch {
	case a.lookAhead < 1 || a.lookAhead > MaxLookAhead:
		return nil, fmt.Errorf("totp: look-ahead must be between 1 and %d", MaxLookAhead)
	case a.resync < 2 || a.resync > MaxResyncWindow:
		return nil, fmt.Errorf("totp: resync window must be between 2 and %d", MaxResyncWindow)
	}
	return a, nil
}

// Authenticate verifies code for subject against the look-ahead window and
// moves the stored counter past the matching value. It returns
// ErrInvalidCode if the code is malformed or matches no value in the
// window, ErrReplay if a concurrent login used it first, and
// ErrNotEnrolled if the subject has no key. Other errors, such as store
// failures, do not wrap authent.ErrUnauthenticated.
func (a *HOTPAuthenticator) Authenticate(ctx context.Context, subject, code string) (authent.Principal, error) {
	return a.authenticate(ctx, subject, a.lookAhead, code)
}

// Resync resynchronizes a token whose counter ran ahead of the look-ahead
// window (RFC 4226 §7.4). The user enters two consecutive codes; if they
// match consecutive counter values within the resync window, the stored
// counter moves past them and the subject is authenticated. Errors are as
// for Authenticate.
func (a *HOTPAuthenticator) Resync(ctx context.Context, subject, code1, code2 string) (authent.Principal, error) {
	return a.authenticate(ctx, subject, a.resync, code1, code2)
}

func (a *HOTPAuthenticator) authenticate(ctx context.Context, subject string, window uint, codes ...string) (authent.Principal, error) {
	cred, err := a.store.LookupHOTPCredential(ctx, subject)
	switch {
	case errors.Is(err, ErrNotEnrolled):
		return authent.Principal{}, ErrNotEnrolled
	case err != nil:
		return authent.Principal{}, fmt.Errorf("totp: looking up credential: %w", err)
	}
	k := cred.Key
	if err := k.validateHOTP(); err != nil {
		return authent.Principal{}, fmt.Errorf("totp: stored key for %q: %w", subject, err)
	}
	for _, code := range codes {
		if len(code) != k.Digits || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return authent.Principal{}, fmt.Errorf("%w: %v", ErrInvalidCode, errMalformedCode)
		}
	}

	n := uint64(len(codes))
	last := uint64(math.MaxUint64) - n
	if cred.Counter > last {
		return authent.Principal{}, ErrInvalidCode
	}
	end := cred.Counter + min(uint64(window), last-cred.Counter+1)
	first, found := k.firstMatchConstantTime(cred.Counter, end, codes)
	if !found {
		return authent.Principal{}, ErrInvalidCode
	}
	next := first + n
	switch err := a.store.AdvanceHOTPCounter(ctx, subject, next); {
	case errors.Is(err, ErrReplay):
		return authent.Principal{}, ErrReplay
	case err != nil:
		return authent.Principal{}, fmt.Errorf("totp: recording used code: %w", err)
	}
	return authent.Principal{
		Subject:  subject,
		Method:   authent.MethodHOTP,
		AuthTime: time.Now(),
	}, nil
}

// firstMatchConstantTime returns the first counter c in [from, end) at
// which codes equal the values from c on.
func (k Key) firstMatchConstantTime(from, end uint64, codes []string) (uint64, bool) {
	first, found := uint64(0), false
	for c := from; c < end; c++ {
		ok := 1
		for i, code := range codes {
			ok &= subtle.ConstantTimeCompare([]byte(k.hotp(c+uint64(i))), []byte(code))
		}
		if ok == 1 && !found {
			first, found = c, true
		}
	}
	return first, found
}
