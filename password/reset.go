package password

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tohshi/authent"
)

var (
	// ErrInvalidResetToken is returned by Redeem when a token is malformed,
	// unknown, already used or expired. It wraps authent.ErrUnauthenticated.
	ErrInvalidResetToken = fmt.Errorf("password: invalid reset token: %w", authent.ErrUnauthenticated)
	// ErrResetTokenNotFound must be returned by
	// ResetTokenStore.TakeResetToken when no token has the given hash.
	ErrResetTokenNotFound = errors.New("password: reset token not found")
)

// ResetToken is the stored form of a password reset token. The token itself
// is never stored, so a leaked store does not yield usable tokens.
type ResetToken struct {
	// Hash is the SHA-256 digest of the decoded token.
	Hash [sha256.Size]byte
	// Subject is the account whose password the token resets.
	Subject string
	// ExpiresAt is when the token stops being accepted.
	ExpiresAt time.Time
}

// ResetTokenStore persists reset tokens.
type ResetTokenStore interface {
	// PutResetToken stores t and deletes every other token of t.Subject.
	PutResetToken(ctx context.Context, t ResetToken) error
	// TakeResetToken removes the token with the given hash and returns it,
	// or returns ErrResetTokenNotFound. It must be atomic: of concurrent
	// calls with the same hash, at most one returns the token. In SQL, use
	// DELETE ... RETURNING, or SELECT ... FOR UPDATE and DELETE in one
	// transaction.
	TakeResetToken(ctx context.Context, hash [sha256.Size]byte) (ResetToken, error)
}

// ResetManager issues and redeems single-use password reset tokens.
type ResetManager struct {
	store ResetTokenStore
	ttl   time.Duration
	now   func() time.Time
}

// ResetOption configures a ResetManager.
type ResetOption func(*ResetManager)

// WithResetTTL sets how long a token is valid. The default is 30 minutes.
func WithResetTTL(d time.Duration) ResetOption { return func(m *ResetManager) { m.ttl = d } }

// WithResetClock overrides the clock used for expiry.
func WithResetClock(now func() time.Time) ResetOption {
	return func(m *ResetManager) { m.now = now }
}

// NewResetManager returns a ResetManager backed by store.
func NewResetManager(store ResetTokenStore, opts ...ResetOption) (*ResetManager, error) {
	m := &ResetManager{store: store, ttl: 30 * time.Minute, now: time.Now}
	for _, opt := range opts {
		opt(m)
	}
	if store == nil || m.ttl <= 0 || m.now == nil {
		return nil, errors.New("password: invalid reset manager configuration")
	}
	return m, nil
}

const resetTokenBytes = 32

var resetB64 = base64.RawURLEncoding.Strict()

// Issue creates a token for subject. Only the newest token of a subject is
// valid: issuing one invalidates the earlier ones.
func (m *ResetManager) Issue(ctx context.Context, subject string) (string, error) {
	if subject == "" {
		return "", errors.New("password: empty reset subject")
	}
	raw := make([]byte, resetTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("password: generating reset token: %w", err)
	}
	t := ResetToken{Hash: sha256.Sum256(raw), Subject: subject, ExpiresAt: m.now().Add(m.ttl)}
	if err := m.store.PutResetToken(ctx, t); err != nil {
		return "", fmt.Errorf("password: storing reset token: %w", err)
	}
	return resetB64.EncodeToString(raw), nil
}

// Redeem consumes token and returns the subject it was issued for. A token
// is accepted once; it is consumed even if it has expired. Set the new
// password after Redeem succeeds. If that fails, the user needs a new token.
func (m *ResetManager) Redeem(ctx context.Context, token string) (string, error) {
	raw, err := resetB64.DecodeString(token)
	if err != nil || len(raw) != resetTokenBytes {
		return "", ErrInvalidResetToken
	}
	t, err := m.store.TakeResetToken(ctx, sha256.Sum256(raw))
	switch {
	case errors.Is(err, ErrResetTokenNotFound):
		return "", ErrInvalidResetToken
	case err != nil:
		return "", fmt.Errorf("password: taking reset token: %w", err)
	}
	if !m.now().Before(t.ExpiresAt) {
		return "", ErrInvalidResetToken
	}
	return t.Subject, nil
}

// MemoryResetStore is an in-process ResetTokenStore. It holds at most one
// token per subject.
type MemoryResetStore struct {
	mu        sync.Mutex
	byHash    map[[sha256.Size]byte]ResetToken
	bySubject map[string][sha256.Size]byte
}

// NewMemoryResetStore returns an empty MemoryResetStore.
func NewMemoryResetStore() *MemoryResetStore {
	return &MemoryResetStore{
		byHash:    map[[sha256.Size]byte]ResetToken{},
		bySubject: map[string][sha256.Size]byte{},
	}
}

// PutResetToken stores t, replacing the subject's previous token.
func (s *MemoryResetStore) PutResetToken(_ context.Context, t ResetToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.bySubject[t.Subject]; ok {
		delete(s.byHash, old)
	}
	s.byHash[t.Hash] = t
	s.bySubject[t.Subject] = t.Hash
	return nil
}

// TakeResetToken removes and returns the token with the given hash.
func (s *MemoryResetStore) TakeResetToken(_ context.Context, hash [sha256.Size]byte) (ResetToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byHash[hash]
	if !ok {
		return ResetToken{}, ErrResetTokenNotFound
	}
	delete(s.byHash, hash)
	delete(s.bySubject, t.Subject)
	return t, nil
}
