package jwt

import (
	"context"
	"sync"
	"time"
)

// ReplayCache remembers token identifiers for replay detection, as used by
// WithReplayCache and by dpop.Verifier. Implementations backed by a shared
// store, such as Redis SET NX with an expiry, let several servers detect
// replays together.
type ReplayCache interface {
	// Add records id for ttl. It reports false if id is already recorded
	// and has not expired. id is a fixed-length hash, never a raw "jti".
	Add(ctx context.Context, id string, ttl time.Duration) (bool, error)
}

// MemoryReplayCache is an in-process ReplayCache. It suits a single
// server; behind a load balancer, use a shared store instead. It is safe
// for concurrent use.
type MemoryReplayCache struct {
	mu        sync.Mutex
	seen      map[string]time.Time // id -> expiry
	nextSweep time.Time
	now       func() time.Time
}

// NewMemoryReplayCache returns an empty MemoryReplayCache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{seen: map[string]time.Time{}, now: time.Now}
}

// Add implements ReplayCache.
func (c *MemoryReplayCache) Add(_ context.Context, id string, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !now.Before(c.nextSweep) {
		for k, exp := range c.seen {
			if !now.Before(exp) {
				delete(c.seen, k)
			}
		}
		c.nextSweep = now.Add(time.Minute)
	}
	if exp, ok := c.seen[id]; ok && now.Before(exp) {
		return false, nil
	}
	c.seen[id] = now.Add(max(ttl, time.Second))
	return true, nil
}
