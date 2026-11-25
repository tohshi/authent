package session

import (
	"bytes"
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-process Store, suitable for tests and single-instance
// deployments. Expired sessions are removed lazily and by DeleteExpired.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]Record
	now     func() time.Time
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]Record{}, now: time.Now}
}

// live returns the unexpired record under key, removing an expired one.
// The caller must hold m.mu.
func (m *MemoryStore) live(key string) (Record, bool) {
	r, ok := m.records[key]
	if ok && !m.now().Before(r.ExpiresAt) {
		delete(m.records, key)
		return Record{}, false
	}
	return r, ok
}

func (m *MemoryStore) Load(_ context.Context, key string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.live(key)
	if !ok {
		return Record{}, ErrNotFound
	}
	r.Data = bytes.Clone(r.Data)
	return r, nil
}

func (m *MemoryStore) Save(_ context.Context, key string, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, _ := m.live(key)
	if r.Version != cur.Version+1 {
		return ErrConflict
	}
	r.Data = bytes.Clone(r.Data)
	m.records[key] = r
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, key string, version uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, _ := m.live(key)
	if version != 0 && cur.Version != version {
		return ErrConflict
	}
	delete(m.records, key)
	return nil
}

// DeleteExpired removes all expired sessions. Call it periodically to bound
// memory use.
func (m *MemoryStore) DeleteExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, r := range m.records {
		if !now.Before(r.ExpiresAt) {
			delete(m.records, k)
		}
	}
}

// Len returns the number of stored sessions, including expired ones not yet
// removed.
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.records)
}
