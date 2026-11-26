package apikey

import (
	"context"
	"errors"
	"sync"
	"time"
)

// MemoryStore is an in-process Store, suitable for tests and
// single-instance deployments.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]Record
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{records: map[string]Record{}} }

func (m *MemoryStore) Create(_ context.Context, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.records[r.ID]; ok {
		return errors.New("apikey: duplicate key ID")
	}
	m.records[r.ID] = r
	return nil
}

func (m *MemoryStore) Lookup(_ context.Context, id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r, nil
}

func (m *MemoryStore) Revoke(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return ErrNotFound
	}
	if r.RevokedAt.IsZero() {
		r.RevokedAt = at
		m.records[id] = r
	}
	return nil
}
