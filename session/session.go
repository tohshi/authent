// Package session manages server-side sessions without depending on any
// HTTP framework.
//
// The caller transports the session token (for example in a cookie with
// Secure, HttpOnly and SameSite set) and passes it to the Manager. The
// Manager never hands the raw token to the Store: records are keyed by the
// SHA-256 hash of the token, so a leaked store does not yield usable
// session tokens.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/tohshi/authent"
)

var (
	// ErrInvalidSession is returned when a token is malformed, unknown or
	// expired. It wraps authent.ErrUnauthenticated.
	ErrInvalidSession = fmt.Errorf("session: invalid session: %w", authent.ErrUnauthenticated)
	// ErrNotFound must be returned by Store.Load for unknown or expired keys.
	ErrNotFound = errors.New("session: not found")
)

// Session is the state stored for a session.
type Session struct {
	Subject    string
	Issuer     string
	AuthMethod authent.Method
	AuthTime   time.Time
	// Values holds application data. Call Manager.Save after changing it.
	Values map[string]string
	// CSRFToken is a per-session synchronizer token. Embed it in forms or
	// headers and check it with VerifyCSRF on state-changing requests.
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time

	key string // store key of the session; set by the Manager
}

// Principal returns the authenticated subject of the session.
func (s *Session) Principal() authent.Principal {
	return authent.Principal{
		Subject:  s.Subject,
		Issuer:   s.Issuer,
		Method:   authent.MethodSession,
		AuthTime: s.AuthTime,
		Claims:   map[string]any{"auth_method": string(s.AuthMethod)},
	}
}

// VerifyCSRF reports whether token equals the session's CSRF token, in
// constant time.
func (s *Session) VerifyCSRF(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.CSRFToken)) == 1
}

func (s Session) clone() Session {
	s.Values = maps.Clone(s.Values)
	return s
}

// Store persists sessions. Keys are opaque, already-hashed identifiers.
// Implementations must be safe for concurrent use.
type Store interface {
	// Load returns ErrNotFound if key is unknown or has expired.
	Load(ctx context.Context, key string) (Session, error)
	// Save creates or replaces the session. The store may discard it after
	// expiresAt.
	Save(ctx context.Context, key string, s Session, expiresAt time.Time) error
	// Delete removes the session. Deleting an unknown key is not an error.
	Delete(ctx context.Context, key string) error
}

// Manager creates, validates, rotates and destroys sessions.
type Manager struct {
	store           Store
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	touchInterval   time.Duration
	now             func() time.Time
}

// Option configures a Manager.
type Option func(*Manager)

// WithIdleTimeout sets how long a session survives without activity.
// The default is 30 minutes.
func WithIdleTimeout(d time.Duration) Option { return func(m *Manager) { m.idleTimeout = d } }

// WithAbsoluteTimeout sets the maximum lifetime of a session regardless of
// activity. The default is 24 hours.
func WithAbsoluteTimeout(d time.Duration) Option {
	return func(m *Manager) { m.absoluteTimeout = d }
}

// WithTouchInterval sets how often activity is written back to the store,
// trading idle-timeout precision for fewer writes. The default is 1 minute.
func WithTouchInterval(d time.Duration) Option { return func(m *Manager) { m.touchInterval = d } }

// WithClock overrides the clock, for tests.
func WithClock(now func() time.Time) Option { return func(m *Manager) { m.now = now } }

// NewManager returns a Manager backed by store.
func NewManager(store Store, opts ...Option) (*Manager, error) {
	m := &Manager{
		store:           store,
		idleTimeout:     30 * time.Minute,
		absoluteTimeout: 24 * time.Hour,
		touchInterval:   time.Minute,
		now:             time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	switch {
	case store == nil:
		return nil, errors.New("session: nil Store")
	case m.idleTimeout <= 0 || m.absoluteTimeout <= 0:
		return nil, errors.New("session: timeouts must be positive")
	case m.touchInterval < 0 || m.touchInterval >= m.idleTimeout:
		return nil, errors.New("session: touch interval must be in [0, idle timeout)")
	}
	return m, nil
}

const tokenBytes = 32

var b64 = base64.RawURLEncoding.Strict()

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: generating token: %w", err)
	}
	return b64.EncodeToString(b), nil
}

// storeKey maps a token to its store key, rejecting malformed tokens
// before they reach the store.
func storeKey(token string) (string, bool) {
	raw, err := b64.DecodeString(token)
	if err != nil || len(raw) != tokenBytes || b64.EncodeToString(raw) != token {
		return "", false
	}
	sum := sha256.Sum256(raw)
	return b64.EncodeToString(sum[:]), true
}

// Create starts a session for p and returns its token, which the caller
// must transport to the client. Call it after every successful login so
// that a session ID set before login is never reused (session fixation).
func (m *Manager) Create(ctx context.Context, p authent.Principal) (string, *Session, error) {
	now := m.now()
	s := &Session{
		Subject:    p.Subject,
		Issuer:     p.Issuer,
		AuthMethod: p.Method,
		AuthTime:   p.AuthTime,
		Values:     map[string]string{},
		CreatedAt:  now,
		LastSeenAt: now,
	}
	if s.AuthTime.IsZero() {
		s.AuthTime = now
	}
	token, err := m.assignToken(s)
	if err != nil {
		return "", nil, err
	}
	if err := m.save(ctx, s); err != nil {
		return "", nil, err
	}
	return token, s, nil
}

// assignToken gives s a fresh token, store key and CSRF token.
func (m *Manager) assignToken(s *Session) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	csrf, err := newToken()
	if err != nil {
		return "", err
	}
	s.key, _ = storeKey(token)
	s.CSRFToken = csrf
	return token, nil
}

// Get returns the session for token. It returns ErrInvalidSession if the
// token is malformed, unknown, or past its idle or absolute timeout.
func (m *Manager) Get(ctx context.Context, token string) (*Session, error) {
	key, ok := storeKey(token)
	if !ok {
		return nil, ErrInvalidSession
	}
	stored, err := m.store.Load(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidSession
	}
	if err != nil {
		return nil, fmt.Errorf("session: loading: %w", err)
	}
	s := &stored
	s.key = key

	now := m.now()
	if !now.Before(m.expiresAt(s)) {
		if err := m.store.Delete(ctx, key); err != nil {
			return nil, fmt.Errorf("session: deleting expired session: %w", err)
		}
		return nil, ErrInvalidSession
	}
	if now.Sub(s.LastSeenAt) >= m.touchInterval {
		s.LastSeenAt = now
		if err := m.save(ctx, s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Save persists changes to s, which must come from Create, Get or Rotate.
// Concurrent saves of the same session are last-write-wins.
func (m *Manager) Save(ctx context.Context, s *Session) error {
	if s.key == "" {
		return errors.New("session: Save of a session not obtained from the Manager")
	}
	return m.save(ctx, s)
}

func (m *Manager) save(ctx context.Context, s *Session) error {
	if err := m.store.Save(ctx, s.key, s.clone(), m.expiresAt(s)); err != nil {
		return fmt.Errorf("session: saving: %w", err)
	}
	return nil
}

func (m *Manager) expiresAt(s *Session) time.Time {
	idle := s.LastSeenAt.Add(m.idleTimeout)
	abs := s.CreatedAt.Add(m.absoluteTimeout)
	if idle.Before(abs) {
		return idle
	}
	return abs
}

// Rotate replaces the session's token and CSRF token, keeping its data and
// absolute timeout, and invalidates the old token. Call it when the
// session's privileges change, for example after re-authentication.
func (m *Manager) Rotate(ctx context.Context, token string) (string, *Session, error) {
	s, err := m.Get(ctx, token)
	if err != nil {
		return "", nil, err
	}
	oldKey := s.key
	newTok, err := m.assignToken(s)
	if err != nil {
		return "", nil, err
	}
	s.LastSeenAt = m.now()
	if err := m.save(ctx, s); err != nil {
		return "", nil, err
	}
	if err := m.store.Delete(ctx, oldKey); err != nil {
		return "", nil, fmt.Errorf("session: deleting rotated session: %w", err)
	}
	return newTok, s, nil
}

// Destroy ends the session for token (logout). Destroying an invalid or
// unknown token is not an error.
func (m *Manager) Destroy(ctx context.Context, token string) error {
	key, ok := storeKey(token)
	if !ok {
		return nil
	}
	if err := m.store.Delete(ctx, key); err != nil {
		return fmt.Errorf("session: deleting: %w", err)
	}
	return nil
}
