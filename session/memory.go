package session

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-process Store, suitable for tests and single-instance
// deployments. Expired sessions are removed lazily and by DeleteExpired.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]memoryEntry
	now      func() time.Time
}

type memoryEntry struct {
	s         Session
	expiresAt time.Time
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sessions: map[string]memoryEntry{}, now: time.Now}
}

func (m *MemoryStore) Load(_ context.Context, key string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.sessions[key]
	if !ok {
		return Session{}, ErrNotFound
	}
	if !m.now().Before(e.expiresAt) {
		delete(m.sessions, key)
		return Session{}, ErrNotFound
	}
	return e.s.clone(), nil
}

func (m *MemoryStore) Save(_ context.Context, key string, s Session, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[key] = memoryEntry{s: s.clone(), expiresAt: expiresAt}
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, key)
	return nil
}

// DeleteExpired removes all expired sessions. Call it periodically to bound
// memory use.
func (m *MemoryStore) DeleteExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, e := range m.sessions {
		if !now.Before(e.expiresAt) {
			delete(m.sessions, k)
		}
	}
}

// Len returns the number of stored sessions, including expired ones not yet
// removed.
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}
