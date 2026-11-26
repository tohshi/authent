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
	mu       sync.Mutex
	records  map[string]Record
	subjects map[string]map[string]bool // subject -> keys
	now      func() time.Time
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]Record{}, subjects: map[string]map[string]bool{}, now: time.Now}
}

// live returns the unexpired record under key, removing an expired one.
// The caller must hold m.mu.
func (m *MemoryStore) live(key string) (Record, bool) {
	r, ok := m.records[key]
	if ok && !m.now().Before(r.ExpiresAt) {
		m.remove(key)
		return Record{}, false
	}
	return r, ok
}

// remove deletes key and its index entry. The caller must hold m.mu.
func (m *MemoryStore) remove(key string) {
	r, ok := m.records[key]
	if !ok {
		return
	}
	delete(m.records, key)
	keys := m.subjects[r.Subject]
	delete(keys, key)
	if len(keys) == 0 {
		delete(m.subjects, r.Subject)
	}
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
	m.remove(key)
	r.Data = bytes.Clone(r.Data)
	m.records[key] = r
	if m.subjects[r.Subject] == nil {
		m.subjects[r.Subject] = map[string]bool{}
	}
	m.subjects[r.Subject][key] = true
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, key string, version uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, _ := m.live(key)
	if version != 0 && cur.Version != version {
		return ErrConflict
	}
	m.remove(key)
	return nil
}

func (m *MemoryStore) List(_ context.Context, subject string) (map[string]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]Record{}
	for key := range m.subjects[subject] {
		if r, ok := m.live(key); ok {
			r.Data = bytes.Clone(r.Data)
			out[key] = r
		}
	}
	return out, nil
}

func (m *MemoryStore) DeleteSubject(_ context.Context, subject string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.subjects[subject] {
		m.remove(key)
	}
	return nil
}

// DeleteExpired removes all expired sessions. Call it periodically to bound
// memory use.
func (m *MemoryStore) DeleteExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.records {
		m.live(key)
	}
}

// Len returns the number of stored sessions, including expired ones not yet
// removed.
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.records)
}
