// Package testenv connects integration tests to the external services they
// need. A test skips when its service is not configured, unless
// AUTHENT_REQUIRE_INTEGRATION=1 is set, as it is in CI, so a missing service
// fails the run instead of silently skipping it.
package testenv

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	postgresEnv = "AUTHENT_POSTGRES_DSN"
	redisEnv    = "AUTHENT_REDIS_ADDR"
	requireEnv  = "AUTHENT_REQUIRE_INTEGRATION"
)

func lookup(t testing.TB, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v != "" {
		return v
	}
	if os.Getenv(requireEnv) == "1" {
		t.Fatalf("%s is not set but %s=1", name, requireEnv)
	}
	t.Skipf("%s is not set", name)
	return ""
}

// Postgres opens a connection pool to the database named by
// AUTHENT_POSTGRES_DSN and closes it when the test ends.
func Postgres(t testing.TB) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", lookup(t, postgresEnv))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}
	return db
}

// RedisAddr returns the host:port in AUTHENT_REDIS_ADDR.
func RedisAddr(t testing.TB) string {
	t.Helper()
	return lookup(t, redisEnv)
}
