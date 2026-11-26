package session

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound must be returned by Store.Load for unknown or expired keys.
	ErrNotFound = errors.New("session: not found")
	// ErrConflict is returned when a session was changed or ended since it
	// was loaded, so a write based on it would lose the other change. It is
	// not an authentication failure: load the session again and retry.
	ErrConflict = errors.New("session: conflicting concurrent update")
)

// Record is the stored form of a session. Data is encoded by the Manager;
// a Store keeps it opaque.
type Record struct {
	// Subject is the session's subject, which the store indexes. It never
	// changes after a key's first Save.
	Subject string
	// Version starts at 1 and grows by one with every save.
	Version uint64
	// ExpiresAt is when the store may discard the record. The Manager
	// enforces the timeouts itself, so it remains the source of truth.
	ExpiresAt time.Time
	Data      []byte
}

// Store persists sessions. Keys are opaque, already-hashed identifiers.
// Implementations must be safe for concurrent use, must not retain or
// modify the Data slices they are passed or return, must compare subjects
// byte by byte, and must treat a record as deleted once its ExpiresAt is
// not after the current time.
//
// The sessiontest package provides a conformance suite.
type Store interface {
	// Load returns ErrNotFound if key is unknown or has expired.
	Load(ctx context.Context, key string) (Record, error)
	// Save stores r under key as one atomic compare-and-swap. If r.Version
	// is 1, key must be new; otherwise key must hold version r.Version-1.
	// If not, Save returns ErrConflict and changes nothing.
	Save(ctx context.Context, key string, r Record) error
	// Delete removes key. If version is not 0, it removes key only if key
	// holds that version, and returns ErrConflict otherwise. Deleting an
	// unknown key with version 0 is not an error.
	Delete(ctx context.Context, key string, version uint64) error
	// List returns the unexpired records of subject, by key.
	List(ctx context.Context, subject string) (map[string]Record, error)
	// DeleteSubject atomically removes every record of subject. A Save
	// that completed before DeleteSubject started does not survive it.
	DeleteSubject(ctx context.Context, subject string) error
}
