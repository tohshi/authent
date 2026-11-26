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
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/tohshi/authent"
)

// ErrInvalidSession is returned when a token is malformed, unknown or
// expired. It wraps authent.ErrUnauthenticated.
var ErrInvalidSession = fmt.Errorf("session: invalid session: %w", authent.ErrUnauthenticated)

// Factor is an authentication method the session's subject passed, and
// when it last did.
type Factor struct {
	Method authent.Method `json:"method"`
	Time   time.Time      `json:"time"`
}

// Session is the state stored for a session. Its authentication state
// changes only through the Manager; application data is read and written
// with Key.
type Session struct {
	st      state
	key     string // store key of the session; set by the Manager
	version uint64 // version of the stored record s was loaded from
}

// state is the part of a session encoded into Record.Data, except for
// Subject, which is Record.Subject.
type state struct {
	Subject    string                    `json:"-"`
	Issuer     string                    `json:"iss,omitempty"`
	Factors    []Factor                  `json:"factors"`
	CSRFToken  string                    `json:"csrf"`
	CreatedAt  time.Time                 `json:"created"`
	LastSeenAt time.Time                 `json:"last_seen"`
	Values     map[string]jsontext.Value `json:"values,omitempty"`
}

// Subject returns the authenticated subject.
func (s *Session) Subject() string { return s.st.Subject }

// Handle identifies the session without revealing its token, for showing
// a subject's sessions and revoking one with Manager.Revoke. It changes
// when the token does.
func (s *Session) Handle() string { return s.key }

// Issuer returns who vouched for the subject when the session was created.
func (s *Session) Issuer() string { return s.st.Issuer }

// Factors returns the authentication methods the subject passed in this
// session, each once, in the order they were first passed.
func (s *Session) Factors() []Factor { return slices.Clone(s.st.Factors) }

// CSRFToken returns the per-session synchronizer token. Embed it in forms
// or headers and check it with VerifyCSRF on state-changing requests.
func (s *Session) CSRFToken() string { return s.st.CSRFToken }

// CreatedAt returns when the session was created; the absolute timeout
// counts from it.
func (s *Session) CreatedAt() time.Time { return s.st.CreatedAt }

// LastSeenAt returns the last recorded activity; the idle timeout counts
// from it.
func (s *Session) LastSeenAt() time.Time { return s.st.LastSeenAt }

// Principal returns the authenticated subject of the session. AuthTime is
// the most recent authentication, and the "amr" claim lists the methods
// of Factors as a []string.
func (s *Session) Principal() authent.Principal {
	amr := make([]string, len(s.st.Factors))
	var last time.Time
	for i, f := range s.st.Factors {
		amr[i] = string(f.Method)
		if f.Time.After(last) {
			last = f.Time
		}
	}
	return authent.Principal{
		Subject:  s.st.Subject,
		Issuer:   s.st.Issuer,
		Method:   authent.MethodSession,
		AuthTime: last,
		Claims:   map[string]any{"amr": amr},
	}
}

// AuthenticatedSince reports whether the subject passed every listed
// method at or after t. With no methods, it reports whether the most recent
// authentication, by any method, was at or after t. Use it before
// sensitive actions, and call Manager.StepUp when it reports false. A zero
// t places no limit on the age.
func (s *Session) AuthenticatedSince(t time.Time, methods ...authent.Method) bool {
	if len(methods) == 0 {
		return slices.ContainsFunc(s.st.Factors, func(f Factor) bool { return !f.Time.Before(t) })
	}
	for _, m := range methods {
		i := slices.IndexFunc(s.st.Factors, func(f Factor) bool { return f.Method == m })
		if i < 0 || s.st.Factors[i].Time.Before(t) {
			return false
		}
	}
	return true
}

// VerifyCSRF reports whether token equals the session's CSRF token, in
// constant time.
func (s *Session) VerifyCSRF(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.st.CSRFToken)) == 1
}

func (s *Session) addFactor(f Factor) {
	i := slices.IndexFunc(s.st.Factors, func(g Factor) bool { return g.Method == f.Method })
	if i < 0 {
		s.st.Factors = append(s.st.Factors, f)
	} else if f.Time.After(s.st.Factors[i].Time) {
		s.st.Factors[i].Time = f.Time
	}
}

func decode(key string, r Record) (*Session, error) {
	s := &Session{key: key, version: r.Version}
	if err := json.Unmarshal(r.Data, &s.st); err != nil {
		return nil, fmt.Errorf("session: decoding stored session: %w", err)
	}
	s.st.Subject = r.Subject
	if s.st.Subject == "" || len(s.st.Factors) == 0 {
		return nil, errors.New("session: stored session has no subject or factors")
	}
	return s, nil
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

// decodeToken returns the bytes of a token or store key, which are
// canonical unpadded base64url of 32 bytes. It rejects anything else
// before it reaches the store.
func decodeToken(s string) ([]byte, bool) {
	raw, err := b64.DecodeString(s)
	if err != nil || len(raw) != tokenBytes || b64.EncodeToString(raw) != s {
		return nil, false
	}
	return raw, true
}

func storeKey(token string) (string, bool) {
	raw, ok := decodeToken(token)
	if !ok {
		return "", false
	}
	sum := sha256.Sum256(raw)
	return b64.EncodeToString(sum[:]), true
}

// Create starts a session for p and returns its token, which the caller
// must transport to the client. Call it after every successful login so
// that a session ID set before login is never reused (session fixation).
// The session records p.Method as its first factor.
func (m *Manager) Create(ctx context.Context, p authent.Principal) (string, *Session, error) {
	if p.Subject == "" || p.Method == "" {
		return "", nil, errors.New("session: principal without subject or method")
	}
	now := m.now()
	s := &Session{st: state{
		Subject:    p.Subject,
		Issuer:     p.Issuer,
		Factors:    []Factor{m.factor(p)},
		CreatedAt:  now,
		LastSeenAt: now,
	}}
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
	s.st.CSRFToken = csrf
	return token, nil
}

// factor returns the factor p authenticated with. An AuthTime in the
// future, or none, counts as now.
func (m *Manager) factor(p authent.Principal) Factor {
	now := m.now()
	if p.AuthTime.IsZero() || p.AuthTime.After(now) {
		return Factor{Method: p.Method, Time: now}
	}
	return Factor{Method: p.Method, Time: p.AuthTime}
}

// Get returns the session for token. It returns ErrInvalidSession if the
// token is malformed, unknown, or past its idle or absolute timeout.
func (m *Manager) Get(ctx context.Context, token string) (*Session, error) {
	key, ok := storeKey(token)
	if !ok {
		return nil, ErrInvalidSession
	}
	s, err := m.load(ctx, key)
	if err != nil {
		return nil, err
	}
	now := m.now()
	if now.Sub(s.st.LastSeenAt) < m.touchInterval {
		return s, nil
	}
	s.st.LastSeenAt = now
	err = m.save(ctx, s)
	if errors.Is(err, ErrConflict) {
		// A concurrent request saved the session first. Its copy is at
		// least as recent as this one, so use it instead of failing.
		return m.load(ctx, key)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (m *Manager) load(ctx context.Context, key string) (*Session, error) {
	r, err := m.store.Load(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidSession
	}
	if err != nil {
		return nil, fmt.Errorf("session: loading: %w", err)
	}
	s, err := decode(key, r)
	if err != nil {
		return nil, err
	}
	if !m.now().Before(m.expiresAt(s)) {
		if err := m.store.Delete(ctx, key, 0); err != nil {
			return nil, fmt.Errorf("session: deleting expired session: %w", err)
		}
		return nil, ErrInvalidSession
	}
	return s, nil
}

// Save persists changes to the values of s, which must come from the
// Manager.
// If the session was saved, rotated or destroyed since s was obtained, Save
// returns an error wrapping ErrConflict and stores nothing; get the session
// again and reapply the change. A session past its timeout returns
// ErrInvalidSession.
func (m *Manager) Save(ctx context.Context, s *Session) error {
	if s.key == "" {
		return errors.New("session: Save of a session not obtained from the Manager")
	}
	return m.save(ctx, s)
}

func (m *Manager) save(ctx context.Context, s *Session) error {
	expiresAt := m.expiresAt(s)
	if !m.now().Before(expiresAt) {
		return ErrInvalidSession
	}
	data, err := json.Marshal(s.st)
	if err != nil {
		return fmt.Errorf("session: encoding: %w", err)
	}
	r := Record{Subject: s.st.Subject, Version: s.version + 1, ExpiresAt: expiresAt, Data: data}
	if err := m.store.Save(ctx, s.key, r); err != nil {
		return fmt.Errorf("session: saving: %w", err)
	}
	s.version = r.Version
	return nil
}

func (m *Manager) expiresAt(s *Session) time.Time {
	idle := s.st.LastSeenAt.Add(m.idleTimeout)
	abs := s.st.CreatedAt.Add(m.absoluteTimeout)
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
	return m.rotate(ctx, s)
}

// StepUp records that the session's subject passed another authentication
// factor, p.Method, and rotates the session like Rotate. p must come from
// an authenticator and name the session's Subject and Issuer; otherwise
// StepUp returns an error wrapping authent.ErrUnauthenticated and leaves
// the session unchanged. Passing a method again updates its time, which
// is how a caller records a fresh re-authentication.
func (m *Manager) StepUp(ctx context.Context, token string, p authent.Principal) (string, *Session, error) {
	s, err := m.Get(ctx, token)
	if err != nil {
		return "", nil, err
	}
	if p.Method == "" || p.Subject != s.st.Subject || p.Issuer != s.st.Issuer {
		return "", nil, fmt.Errorf("session: step-up principal does not match the session: %w", authent.ErrUnauthenticated)
	}
	s.addFactor(m.factor(p))
	return m.rotate(ctx, s)
}

// rotate moves s to a new token. The new record is written before the old
// one is deleted, and the old one is deleted only if it is unchanged, so
// that neither a concurrent save nor a concurrent destroy is lost.
func (m *Manager) rotate(ctx context.Context, s *Session) (string, *Session, error) {
	oldKey, oldVersion := s.key, s.version
	token, err := m.assignToken(s)
	if err != nil {
		return "", nil, err
	}
	s.version = 0
	s.st.LastSeenAt = m.now()
	if err := m.save(ctx, s); err != nil {
		return "", nil, err
	}
	if err := m.store.Delete(ctx, oldKey, oldVersion); err != nil {
		if delErr := m.store.Delete(ctx, s.key, 0); delErr != nil {
			err = errors.Join(err, delErr)
		}
		return "", nil, fmt.Errorf("session: deleting rotated session: %w", err)
	}
	return token, s, nil
}

// Destroy ends the session for token (logout). Destroying an invalid or
// unknown token is not an error.
func (m *Manager) Destroy(ctx context.Context, token string) error {
	key, ok := storeKey(token)
	if !ok {
		return nil
	}
	if err := m.store.Delete(ctx, key, 0); err != nil {
		return fmt.Errorf("session: deleting: %w", err)
	}
	return nil
}

// List returns the unexpired sessions of subject, oldest first, for
// example to show them to the subject. The sessions carry no tokens; use
// Session.Handle to tell them apart and to revoke one.
func (m *Manager) List(ctx context.Context, subject string) ([]*Session, error) {
	records, err := m.store.List(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("session: listing: %w", err)
	}
	now := m.now()
	out := make([]*Session, 0, len(records))
	for key, r := range records {
		if r.Subject != subject {
			continue
		}
		s, err := decode(key, r)
		if err != nil {
			return nil, err
		}
		if now.Before(m.expiresAt(s)) {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b *Session) int {
		if c := a.st.CreatedAt.Compare(b.st.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.key, b.key)
	})
	return out, nil
}

// Revoke ends the session with the given handle if it belongs to subject.
// Pass the subject of the session making the request, so that one subject
// cannot end another's sessions. An unknown, malformed or foreign handle is
// not an error and changes nothing.
func (m *Manager) Revoke(ctx context.Context, subject, handle string) error {
	if _, ok := decodeToken(handle); !ok {
		return nil
	}
	r, err := m.store.Load(ctx, handle)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("session: loading: %w", err)
	}
	if r.Subject != subject {
		return nil
	}
	// The subject of a key never changes, so the check above still holds.
	if err := m.store.Delete(ctx, handle, 0); err != nil {
		return fmt.Errorf("session: deleting: %w", err)
	}
	return nil
}

// RevokeAll ends every session of subject ("log out everywhere"), for
// example after a password change. A session being rotated or stepped up
// at the same time does not survive under its new token.
func (m *Manager) RevokeAll(ctx context.Context, subject string) error {
	if err := m.store.DeleteSubject(ctx, subject); err != nil {
		return fmt.Errorf("session: deleting sessions of subject: %w", err)
	}
	return nil
}
