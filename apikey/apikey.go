// Package apikey issues and verifies API keys: long-lived opaque tokens for
// machine clients.
//
// A key has the form
//
//	<prefix>_<id>_<secret>
//
// for example "myapp_2u4lmyzvh7f6eswq_…". The prefix is chosen by the
// caller so that secret scanners can recognize its keys. The ID is public
// and locates the stored record. The secret segment carries 248 random bits
// and a CRC-32 checksum of the whole key, so mistyped or truncated keys are
// rejected before any store lookup. All segments use lowercase base32
// without padding.
//
// The store keeps only the SHA-256 hash of the secret, so a leaked store
// does not yield usable keys.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"time"

	"github.com/tohshi/authent"
)

var (
	// ErrInvalidKey is returned for keys that are malformed, unknown, wrong,
	// expired or revoked. It wraps authent.ErrUnauthenticated.
	ErrInvalidKey = fmt.Errorf("apikey: invalid key: %w", authent.ErrUnauthenticated)
	// ErrMalformed is returned for keys that do not have this Manager's
	// format, prefix or a valid checksum. It wraps ErrInvalidKey.
	ErrMalformed = fmt.Errorf("%w: malformed", ErrInvalidKey)
	// ErrExpired is returned for keys past their expiry. It wraps ErrInvalidKey.
	ErrExpired = fmt.Errorf("%w: expired", ErrInvalidKey)
	// ErrRevoked is returned for revoked keys. It wraps ErrInvalidKey.
	ErrRevoked = fmt.Errorf("%w: revoked", ErrInvalidKey)
	// ErrNotFound must be returned by Store.Lookup and Store.Revoke for
	// unknown IDs.
	ErrNotFound = errors.New("apikey: not found")
)

const (
	idBytes     = 10
	secretBytes = 31
	sumBytes    = 4
	idLen       = idBytes * 8 / 5
	secretLen   = (secretBytes + sumBytes) * 8 / 5
)

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Record is the stored state of a key.
type Record struct {
	ID string
	// SecretHash is the SHA-256 of the key's random secret bytes.
	SecretHash [sha256.Size]byte
	Subject    string
	CreatedAt  time.Time
	// ExpiresAt is required; a record without it is treated as expired.
	ExpiresAt time.Time
	// RevokedAt is zero unless the key was revoked.
	RevokedAt time.Time
}

// Store persists key records. Implementations must be safe for concurrent
// use.
type Store interface {
	// Create saves a new record. It must fail if the ID already exists.
	Create(ctx context.Context, r Record) error
	// Lookup returns ErrNotFound if id is unknown.
	Lookup(ctx context.Context, id string) (Record, error)
	// Revoke sets RevokedAt to at unless the key is already revoked. It
	// returns ErrNotFound if id is unknown.
	Revoke(ctx context.Context, id string, at time.Time) error
}

// Manager creates, verifies and revokes keys with one prefix.
type Manager struct {
	prefix string
	store  Store
	now    func() time.Time
}

// Option configures a Manager.
type Option func(*Manager)

// WithClock overrides the clock, for tests.
func WithClock(now func() time.Time) Option { return func(m *Manager) { m.now = now } }

// NewManager returns a Manager for keys starting with prefix. The prefix is
// 2 to 16 lowercase letters and digits, starting with a letter.
func NewManager(prefix string, store Store, opts ...Option) (*Manager, error) {
	if !validPrefix(prefix) {
		return nil, fmt.Errorf("apikey: invalid prefix %q", prefix)
	}
	if store == nil {
		return nil, errors.New("apikey: nil Store")
	}
	m := &Manager{prefix: prefix, store: store, now: time.Now}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

func validPrefix(p string) bool {
	if len(p) < 2 || len(p) > 16 || p[0] < 'a' || p[0] > 'z' {
		return false
	}
	for i := 1; i < len(p); i++ {
		if c := p[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// Prefix returns the prefix of the Manager's keys.
func (m *Manager) Prefix() string { return m.prefix }

// Create issues a key for subject that expires at expiresAt. The returned
// key is shown to the client once; only its Record is stored.
func (m *Manager) Create(ctx context.Context, subject string, expiresAt time.Time) (string, Record, error) {
	now := m.now()
	if subject == "" {
		return "", Record{}, errors.New("apikey: empty subject")
	}
	if !expiresAt.After(now) {
		return "", Record{}, errors.New("apikey: expiry must be in the future")
	}
	var raw [idBytes + secretBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", Record{}, fmt.Errorf("apikey: generating key: %w", err)
	}
	id := b32.EncodeToString(raw[:idBytes])
	secret := raw[idBytes:]
	key := format(m.prefix, id, secret)
	r := Record{
		ID:         id,
		SecretHash: sha256.Sum256(secret),
		Subject:    subject,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
	}
	if err := m.store.Create(ctx, r); err != nil {
		return "", Record{}, fmt.Errorf("apikey: saving: %w", err)
	}
	return key, r, nil
}

// Authenticate verifies key and returns the Principal of its subject. The
// key ID is in Claims["key_id"]. Rejected keys return an error wrapping
// ErrInvalidKey; store failures do not.
func (m *Manager) Authenticate(ctx context.Context, key string) (authent.Principal, error) {
	id, secret, ok := parse(m.prefix, key)
	if !ok {
		return authent.Principal{}, ErrMalformed
	}
	r, err := m.store.Lookup(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return authent.Principal{}, ErrInvalidKey
	}
	if err != nil {
		return authent.Principal{}, fmt.Errorf("apikey: lookup: %w", err)
	}
	sum := sha256.Sum256(secret)
	if r.ID != id || subtle.ConstantTimeCompare(sum[:], r.SecretHash[:]) != 1 {
		return authent.Principal{}, ErrInvalidKey
	}
	now := m.now()
	switch {
	case !r.RevokedAt.IsZero():
		return authent.Principal{}, ErrRevoked
	case !now.Before(r.ExpiresAt):
		return authent.Principal{}, ErrExpired
	case r.Subject == "":
		return authent.Principal{}, ErrInvalidKey
	}
	return authent.Principal{
		Subject:  r.Subject,
		Method:   authent.MethodAPIKey,
		AuthTime: now,
		Claims:   map[string]any{"key_id": id},
	}, nil
}

// Revoke revokes the key with the given ID. Revoking a revoked key is not
// an error.
func (m *Manager) Revoke(ctx context.Context, id string) error {
	if err := m.store.Revoke(ctx, id, m.now()); err != nil {
		return fmt.Errorf("apikey: revoking: %w", err)
	}
	return nil
}

func format(prefix, id string, secret []byte) string {
	head := prefix + "_" + id + "_"
	tail := make([]byte, 0, secretBytes+sumBytes)
	tail = append(tail, secret...)
	tail = binary.BigEndian.AppendUint32(tail, checksum(head, secret))
	return head + b32.EncodeToString(tail)
}

func checksum(head string, secret []byte) uint32 {
	c := crc32.ChecksumIEEE([]byte(head))
	return crc32.Update(c, crc32.IEEETable, secret)
}

func parse(prefix, key string) (id string, secret []byte, ok bool) {
	if len(key) != len(prefix)+1+idLen+1+secretLen {
		return "", nil, false
	}
	p, rest, _ := strings.Cut(key, "_")
	id, tail, _ := strings.Cut(rest, "_")
	if p != prefix || len(id) != idLen || len(tail) != secretLen {
		return "", nil, false
	}
	if rawID, err := b32.DecodeString(id); err != nil || len(rawID) != idBytes {
		return "", nil, false
	}
	raw, err := b32.DecodeString(tail)
	if err != nil || len(raw) != secretBytes+sumBytes {
		return "", nil, false
	}
	secret, sum := raw[:secretBytes], raw[secretBytes:]
	if binary.BigEndian.Uint32(sum) != checksum(p+"_"+id+"_", secret) {
		return "", nil, false
	}
	return id, secret, true
}
