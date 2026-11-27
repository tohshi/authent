package session_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/integration/testenv"
	"github.com/tohshi/authent/session"
	"github.com/tohshi/authent/session/sessiontest"
	"github.com/tohshi/authent/session/sqlstore"
)

func newPostgresStore(t *testing.T) *sqlstore.Store {
	t.Helper()
	db := testenv.Postgres(t)
	table := "sessions_" + strings.ToLower(rand.Text()[:12])
	s, err := sqlstore.New(db, sqlstore.PostgreSQL, sqlstore.WithTable(table))
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

func TestSQLStorePostgresRevokeAllRacingRotate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db := testenv.Postgres(t)
	name := strings.ToLower(rand.Text()[:12])
	table := "sessions_" + name
	fn := "block_subject_delete_" + name
	store, err := sqlstore.New(db, sqlstore.PostgreSQL, sqlstore.WithTable(table))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateTable(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP TABLE " + table) })
	m, err := session.NewManager(store)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, _, err := m.Create(ctx, authent.Principal{Subject: "alice", Method: authent.MethodPassword})
	if err != nil {
		t.Fatal(err)
	}

	lockID := time.Now().UnixNano()
	blocker, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	if _, err := blocker.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			blocker.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", lockID)
		}
	}()

	createFn := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF strpos(current_query(), 'WHERE subject = ') > 0 THEN
    PERFORM pg_advisory_xact_lock(%d);
  END IF;
  RETURN NULL;
END $$`, fn, lockID)
	if _, err := db.ExecContext(ctx, createFn); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP FUNCTION " + fn + "() CASCADE") })
	if _, err := db.ExecContext(ctx, "CREATE TRIGGER block_subject_delete BEFORE DELETE ON "+table+" FOR EACH STATEMENT EXECUTE FUNCTION "+fn+"()"); err != nil {
		t.Fatal(err)
	}

	revokeDone := make(chan error, 1)
	go func() { revokeDone <- m.RevokeAll(ctx, "alice") }()
	waitForSQLLock(t, ctx, db, table, "DELETE", "advisory")

	type rotation struct {
		token string
		err   error
	}
	rotateDone := make(chan rotation, 1)
	go func() {
		token, _, err := m.Rotate(ctx, oldToken)
		rotateDone <- rotation{token, err}
	}()
	// The old implementation completes rotation while RevokeAll is blocked.
	// A serialized implementation blocks its INSERT until revocation ends.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case result := <-rotateDone:
			rotateDone <- result
			goto release
		default:
		}
		if sqlLockWaiting(t, ctx, db, table, "INSERT", "relation") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
release:
	if _, err := blocker.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID); err != nil {
		t.Fatal(err)
	}
	locked = false
	if err := <-revokeDone; err != nil {
		t.Fatal(err)
	}
	result := <-rotateDone
	if result.err != nil && result.token != "" {
		t.Fatalf("Rotate returned token with error: %v", result.err)
	}
	if sessions, err := m.List(ctx, "alice"); err != nil || len(sessions) != 0 {
		t.Fatalf("RevokeAll left %d sessions after racing Rotate: %v", len(sessions), err)
	}
}

func waitForSQLLock(t *testing.T, ctx context.Context, db *sql.DB, table, verb, event string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sqlLockWaiting(t, ctx, db, table, verb, event) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s on %s did not wait for %s lock", verb, table, event)
}

func sqlLockWaiting(t *testing.T, ctx context.Context, db *sql.DB, table, verb, event string) bool {
	t.Helper()
	var waiting bool
	pattern := verb + ` % "` + table + `"%`
	err := db.QueryRowContext(ctx, `SELECT EXISTS (
    SELECT 1 FROM pg_stat_activity
    WHERE wait_event_type = 'Lock' AND wait_event = $1 AND query LIKE $2
)`, event, pattern).Scan(&waiting)
	if err != nil {
		t.Fatal(err)
	}
	return waiting
}
