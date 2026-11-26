package password

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tohshi/authent"
)

var (
	// ErrInvalidCredentials is returned by Authenticate when the user does
	// not exist or the password is wrong. The two cases are deliberately
	// indistinguishable. It wraps authent.ErrUnauthenticated.
	ErrInvalidCredentials = fmt.Errorf("password: invalid credentials: %w", authent.ErrUnauthenticated)
	// ErrUserNotFound must be returned by CredentialStore.LookupCredential
	// when no user has the given username.
	ErrUserNotFound = errors.New("password: user not found")
)

// Credential is a stored password hash and the subject it belongs to.
type Credential struct {
	// Subject becomes Principal.Subject. Prefer a stable ID over the
	// username, which users may change.
	Subject string
	// Hash is an encoded hash produced by Hasher.Hash or Policy.Hash, or a
	// legacy hash that Hasher.Verify accepts.
	Hash string
}

// CredentialStore looks up credentials by username.
type CredentialStore interface {
	// LookupCredential returns ErrUserNotFound if the user does not exist.
	LookupCredential(ctx context.Context, username string) (Credential, error)
}

// CredentialUpdater is optionally implemented by a CredentialStore. If it
// is, Authenticate replaces legacy hashes and hashes created with outdated
// parameters after a successful login.
type CredentialUpdater interface {
	UpdateCredential(ctx context.Context, subject, hash string) error
}

// Authenticator authenticates username and password pairs.
type Authenticator struct {
	store     CredentialStore
	hasher    *Hasher
	dummyHash string
	now       func() time.Time
}

// AuthenticatorOption configures an Authenticator.
type AuthenticatorOption func(*Authenticator)

// WithClock overrides the clock used for Principal.AuthTime.
func WithClock(now func() time.Time) AuthenticatorOption {
	return func(a *Authenticator) { a.now = now }
}

// NewAuthenticator returns an Authenticator backed by store.
func NewAuthenticator(store CredentialStore, hasher *Hasher, opts ...AuthenticatorOption) (*Authenticator, error) {
	// Unknown users are verified against this hash so that the response
	// time does not reveal whether a username exists.
	dummy, err := hasher.Hash("authent-dummy-password")
	if err != nil {
		return nil, err
	}
	a := &Authenticator{store: store, hasher: hasher, dummyHash: dummy, now: time.Now}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Authenticate verifies password for username. It returns
// ErrInvalidCredentials if the user does not exist or the password is wrong.
// Other errors, such as store failures, are returned as is and do not wrap
// authent.ErrUnauthenticated.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (authent.Principal, error) {
	cred, err := a.store.LookupCredential(ctx, username)
	switch {
	case errors.Is(err, ErrUserNotFound):
		_ = a.hasher.Verify(password, a.dummyHash)
		return authent.Principal{}, ErrInvalidCredentials
	case err != nil:
		return authent.Principal{}, fmt.Errorf("password: looking up credential: %w", err)
	}

	stored, err := a.hasher.verify(password, cred.Hash)
	switch {
	case errors.Is(err, ErrMismatch):
		return authent.Principal{}, ErrInvalidCredentials
	case err != nil:
		return authent.Principal{}, fmt.Errorf("password: stored hash for %q: %w", cred.Subject, err)
	}

	if err := a.rehashIfNeeded(ctx, cred.Subject, stored, password); err != nil {
		return authent.Principal{}, err
	}
	return authent.Principal{
		Subject:  cred.Subject,
		Method:   authent.MethodPassword,
		AuthTime: a.now(),
	}, nil
}

func (a *Authenticator) rehashIfNeeded(ctx context.Context, subject string, stored storedHash, password string) error {
	updater, ok := a.store.(CredentialUpdater)
	if !ok || stored.current(a.hasher) {
		return nil
	}
	hash, err := a.hasher.hash(password, stored.normalized())
	if err != nil {
		return err
	}
	if err := updater.UpdateCredential(ctx, subject, hash); err != nil {
		return fmt.Errorf("password: upgrading hash: %w", err)
	}
	return nil
}
