package session_test

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/tohshi/authent/integration/testenv"
	"github.com/tohshi/authent/session"
	"github.com/tohshi/authent/session/sessiontest"
)

func newPostgresStore(t *testing.T) *session.SQLStore {
	t.Helper()
	db := testenv.Postgres(t)
	table := "sessions_" + strings.ToLower(rand.Text()[:12])
	s, err := session.NewSQLStore(db, session.PostgreSQL, session.WithSQLTable(table))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTable(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP TABLE " + table) })
	return s
}

func TestSQLStorePostgres(t *testing.T) {
	sessiontest.TestStore(t, func(t *testing.T) session.Store { return newPostgresStore(t) })
}

func TestSQLStorePostgresDeleteExpired(t *testing.T) {
	s := newPostgresStore(t)
	ctx := context.Background()
	for key, exp := range map[string]time.Time{"live": time.Now().Add(time.Hour), "dead": time.Now().Add(-time.Second)} {
		if err := s.Save(ctx, key, session.Record{Subject: "alice", Version: 1, ExpiresAt: exp, Data: []byte("{}")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	// The expired row is gone, not merely hidden: a new record can take
	// its key.
	if err := s.Save(ctx, "dead", session.Record{Subject: "alice", Version: 1, ExpiresAt: time.Now().Add(time.Hour), Data: []byte("{}")}); err != nil {
		t.Fatalf("Save over a deleted expired key: %v", err)
	}
	if _, err := s.Load(ctx, "live"); err != nil {
		t.Fatalf("DeleteExpired removed a live session: %v", err)
	}
}
