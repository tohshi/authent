package jwt_test

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/tohshi/authent/integration/testenv"
	"github.com/tohshi/authent/jwt"
	"github.com/tohshi/authent/jwt/replaytest"
	"github.com/tohshi/authent/jwt/sqlreplay"
)

func newPostgresCache(t *testing.T, opts ...sqlreplay.Option) *sqlreplay.Cache {
	t.Helper()
	db := testenv.Postgres(t)
	table := "replay_" + strings.ToLower(rand.Text()[:12])
	c, err := sqlreplay.New(db, sqlreplay.PostgreSQL, append(opts, sqlreplay.WithTable(table))...)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CreateTable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateTable(context.Background()); err != nil {
		t.Fatalf("CreateTable is not idempotent: %v", err)
	}
	t.Cleanup(func() { db.Exec("DROP TABLE " + table) })
	return c
}

func TestSQLReplayCachePostgres(t *testing.T) {
	replaytest.TestReplayCache(t, func(t *testing.T) jwt.ReplayCache { return newPostgresCache(t) })
}

func TestSQLReplayCachePostgresDeleteExpired(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	c := newPostgresCache(t, sqlreplay.WithClock(func() time.Time { return now }))
	c.Add(ctx, "short", time.Second)
	c.Add(ctx, "long", time.Hour)
	now = now.Add(time.Minute)
	if n, err := c.DeleteExpired(ctx); n != 1 || err != nil {
		t.Fatalf("DeleteExpired = %d, %v, want 1", n, err)
	}
	if ok, _ := c.Add(ctx, "long", time.Hour); ok {
		t.Fatal("DeleteExpired removed a live entry")
	}
}
