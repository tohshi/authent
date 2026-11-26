package jwt_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/tohshi/authent/integration/testenv"
	"github.com/tohshi/authent/jwt"
	"github.com/tohshi/authent/jwt/replaytest"
	"github.com/tohshi/authent/redis/redisreplay"
)

func newRedisCache(t *testing.T) (*redisreplay.Cache, *redis.Client, string) {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: testenv.RedisAddr(t)})
	prefix := "authent-test:" + rand.Text() + ":"
	t.Cleanup(func() {
		ctx := context.Background()
		keys, _ := client.Keys(ctx, prefix+"*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
		client.Close()
	})
	c, err := redisreplay.New(client, redisreplay.WithPrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	return c, client, prefix
}

func TestRedisReplayCache(t *testing.T) {
	replaytest.TestReplayCache(t, func(t *testing.T) jwt.ReplayCache {
		c, _, _ := newRedisCache(t)
		return c
	})
}

func TestRedisReplayCacheSetsExpiry(t *testing.T) {
	ctx := context.Background()
	c, client, prefix := newRedisCache(t)
	if _, err := c.Add(ctx, "id", 90*time.Second); err != nil {
		t.Fatal(err)
	}
	ttl, err := client.PTTL(ctx, prefix+"id").Result()
	if err != nil || ttl <= 89*time.Second || ttl > 90*time.Second {
		t.Fatalf("PTTL = %v, %v; want about 90s", ttl, err)
	}
}
