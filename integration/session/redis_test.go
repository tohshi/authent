package session_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/integration/testenv"
	"github.com/tohshi/authent/redis/redissession"
	"github.com/tohshi/authent/session"
	"github.com/tohshi/authent/session/sessiontest"
)

// newRedisStore returns a store whose keys share a fresh prefix, and
// deletes them when the test ends.
func newRedisStore(t *testing.T) (*redissession.Store, *redis.Client, string) {
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
	s, err := redissession.New(client, redissession.WithPrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	return s, client, prefix
}

func TestRedisStore(t *testing.T) {
	sessiontest.TestStore(t, func(t *testing.T) session.Store {
		s, _, _ := newRedisStore(t)
		return s
	})
}

func TestRedisStoreExpiresKeys(t *testing.T) {
	s, client, prefix := newRedisStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	if err := s.Save(ctx, "k", session.Record{Subject: "alice", Version: 1, ExpiresAt: exp, Data: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	// Both the session and the subject index carry a TTL, so neither
	// outlives the session in Redis.
	for _, key := range []string{prefix + "k:k", prefix + "s:alice"} {
		ttl, err := client.PTTL(ctx, key).Result()
		if err != nil || ttl <= 0 || ttl > time.Minute+time.Second {
			t.Errorf("PTTL(%s) = %v, %v; want about a minute", key, ttl, err)
		}
	}
	if err := s.DeleteSubject(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Exists(ctx, prefix+"k:k", prefix+"s:alice").Result(); err != nil || n != 0 {
		t.Fatalf("%d keys left after DeleteSubject, %v", n, err)
	}
}

func TestRedisStoreServerDown(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: time.Second})
	t.Cleanup(func() { client.Close() })
	s, _ := redissession.New(client)
	m, err := session.NewManager(s)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Get(context.Background(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err == nil || errors.Is(err, session.ErrInvalidSession) {
		t.Fatalf("Get with Redis down: err = %v, want a connection error", err)
	}
}

func TestRedisStoreIndexHoldsOnlyLiveSessions(t *testing.T) {
	s, client, prefix := newRedisStore(t)
	m, err := session.NewManager(s)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	alice := authent.Principal{Subject: "alice", Method: authent.MethodPassword}
	indexSize := func() int64 {
		t.Helper()
		n, err := client.ZCard(ctx, prefix+"s:alice").Result()
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for range 20 {
		tok, _, err := m.Create(ctx, alice)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Destroy(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if n := indexSize(); n != 0 {
		t.Fatalf("after Create+Destroy: index holds %d entries, want 0", n)
	}
	for i := range 20 {
		tok, _, err := m.Create(ctx, alice)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.Rotate(ctx, tok); err != nil {
			t.Fatal(err)
		}
		if n := indexSize(); n != int64(i+1) {
			t.Fatalf("after %d Create+Rotate: index holds %d entries, want %d", i+1, n, i+1)
		}
	}
}

func TestRedisStoreDeleteSubjectSparesOtherSubjects(t *testing.T) {
	s, _, _ := newRedisStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	if err := s.Save(ctx, "k", session.Record{Subject: "old", Version: 1, ExpiresAt: exp, Data: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "k", session.Record{Subject: "new", Version: 2, ExpiresAt: exp, Data: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSubject(ctx, "old"); err != nil {
		t.Fatal(err)
	}
	r, err := s.Load(ctx, "k")
	if err != nil || r.Subject != "new" {
		t.Fatalf("DeleteSubject(old) removed a session of another subject: %+v, %v", r, err)
	}
}
