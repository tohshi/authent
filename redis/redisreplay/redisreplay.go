// Package redisreplay provides a jwt.ReplayCache backed by Redis, so that
// several servers detect replayed tokens and DPoP proofs together.
//
// It lives in the github.com/tohshi/authent/redis module, so that the core
// module keeps no dependencies beyond the standard library and
// golang.org/x.
package redisreplay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultPrefix is the key prefix a Cache uses unless WithPrefix is given.
const DefaultPrefix = "authent:replay:"

// Cache is a jwt.ReplayCache that records each id as a key set with
// SET NX and an expiry, so Redis removes expired entries itself. Each Add
// touches one key, so it also works with Redis Cluster. It is safe for
// concurrent use.
type Cache struct {
	client redis.UniversalClient
	prefix string
}

// Option configures a Cache.
type Option func(*Cache)

// WithPrefix sets the prefix of every key the Cache writes. The default is
// DefaultPrefix.
func WithPrefix(prefix string) Option { return func(c *Cache) { c.prefix = prefix } }

// New returns a Cache that records ids in the Redis server of client.
func New(client redis.UniversalClient, opts ...Option) (*Cache, error) {
	if client == nil {
		return nil, errors.New("redisreplay: nil Redis client")
	}
	c := &Cache{client: client, prefix: DefaultPrefix}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Add implements jwt.ReplayCache. A ttl below one second is raised to one
// second, as in jwt.MemoryReplayCache.
func (c *Cache) Add(ctx context.Context, id string, ttl time.Duration) (bool, error) {
	fresh, err := c.client.SetNX(ctx, c.prefix+id, 1, max(ttl, time.Second)).Result()
	if err != nil {
		return false, fmt.Errorf("redisreplay: add: %w", err)
	}
	return fresh, nil
}
