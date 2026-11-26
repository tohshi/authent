package sqlreplay

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
	"github.com/tohshi/authent/jwt/replaytest"
)

// fakeDB is a database/sql driver that executes the Cache's INSERT and
// DELETE statements against a map, with the semantics of PostgreSQL's
// INSERT ... ON CONFLICT DO UPDATE ... WHERE.
type fakeDB struct {
	mu      sync.Mutex
	rows    map[string]int64 // id -> expires_at
	queries []string
	err     error // returned by every Exec when set
	// affected, when set, replaces the affected-row count of an INSERT.
	affected *int64
}

func (f *fakeDB) Connect(context.Context) (driver.Conn, error) { return fakeConn{f}, nil }
func (f *fakeDB) Driver() driver.Driver                        { return fakeDriver{} }

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use sql.OpenDB") }

type fakeConn struct{ db *fakeDB }

func (fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (fakeConn) Close() error                        { return nil }
func (fakeConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }

func (c fakeConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	f := c.db
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, query)
	if f.err != nil {
		return nil, f.err
	}
	switch {
	case strings.HasPrefix(query, "CREATE "):
		return driver.RowsAffected(0), nil
	case strings.HasPrefix(query, "INSERT "):
		id, exp, now := args[0].Value.(string), args[1].Value.(int64), args[2].Value.(int64)
		var n int64
		if old, ok := f.rows[id]; !ok || old <= now {
			f.rows[id] = exp
			n = 1
		}
		if f.affected != nil {
			n = *f.affected
		}
		return driver.RowsAffected(n), nil
	case strings.HasPrefix(query, "DELETE "):
		now := args[0].Value.(int64)
		var n int64
		for id, exp := range f.rows {
			if exp <= now {
				delete(f.rows, id)
				n++
			}
		}
		return driver.RowsAffected(n), nil
	}
	return nil, errors.New("unexpected query: " + query)
}

func newFake(t *testing.T, dialect Dialect, opts ...Option) (*Cache, *fakeDB) {
	t.Helper()
	f := &fakeDB{rows: map[string]int64{}}
	db := sql.OpenDB(f)
	t.Cleanup(func() { db.Close() })
	c, err := New(db, dialect, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestConformance(t *testing.T) {
	replaytest.TestReplayCache(t, func(t *testing.T) jwt.ReplayCache {
		c, _ := newFake(t, PostgreSQL)
		return c
	})
}

func TestAddUsesClockAndMinimumTTL(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	c, f := newFake(t, PostgreSQL, WithClock(func() time.Time { return now }))
	ctx := context.Background()
	if ok, err := c.Add(ctx, "a", time.Millisecond); !ok || err != nil {
		t.Fatalf("Add = %v, %v", ok, err)
	}
	if got, want := f.rows["a"], now.Add(time.Second).UnixMilli(); got != want {
		t.Fatalf("expires_at = %d, want %d (one second minimum)", got, want)
	}
	now = now.Add(999 * time.Millisecond)
	if ok, _ := c.Add(ctx, "a", time.Minute); ok {
		t.Fatal("replay accepted before expiry")
	}
	now = now.Add(time.Millisecond)
	if ok, _ := c.Add(ctx, "a", time.Minute); !ok {
		t.Fatal("expired id not accepted again")
	}

	c.Add(ctx, "b", time.Hour)
	now = now.Add(30 * time.Second)
	if n, err := c.DeleteExpired(ctx); n != 0 || err != nil {
		t.Fatalf("DeleteExpired = %d, %v, want 0", n, err)
	}
	now = now.Add(time.Hour)
	if n, err := c.DeleteExpired(ctx); n != 2 || err != nil || len(f.rows) != 0 {
		t.Fatalf("DeleteExpired = %d, %v, rows %v", n, err, f.rows)
	}
}

func TestStoreFailuresFailClosed(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("connection reset")
	c, f := newFake(t, PostgreSQL)
	f.err = boom
	if ok, err := c.Add(ctx, "a", time.Minute); ok || !errors.Is(err, boom) || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("Add = %v, %v", ok, err)
	}
	if _, err := c.DeleteExpired(ctx); !errors.Is(err, boom) {
		t.Fatalf("DeleteExpired err = %v", err)
	}
	if err := c.CreateTable(ctx); !errors.Is(err, boom) {
		t.Fatalf("CreateTable err = %v", err)
	}

	two := int64(2)
	c, f = newFake(t, PostgreSQL)
	f.affected = &two
	if ok, err := c.Add(ctx, "a", time.Minute); ok || err == nil {
		t.Fatalf("Add with 2 affected rows = %v, %v", ok, err)
	}
}

func TestVerifierRejectsReplay(t *testing.T) {
	c, _ := newFake(t, SQLite)
	secret := []byte(strings.Repeat("k", 32))
	signer, err := jwt.NewSigner(jwt.HS256, secret)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := jwt.NewHMACKey("", jwt.HS256, secret)
	v, err := jwt.NewVerifier(jwt.NewStaticKeySet(key), jwt.WithAlgorithms(jwt.HS256),
		jwt.WithAnyIssuer(), jwt.WithAnyAudience(), jwt.WithReplayCache(c))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := signer.Sign(jwt.Claims{ID: "j1", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, jwt.ErrReplayed) {
		t.Fatalf("replay err = %v, want jwt.ErrReplayed", err)
	}
}

func TestStatements(t *testing.T) {
	for name, tc := range map[string]struct {
		dialect Dialect
		table   string
		create  []string
		add     string
	}{
		"postgres": {PostgreSQL, "auth.replay",
			[]string{
				`CREATE TABLE IF NOT EXISTS "auth"."replay" (id TEXT COLLATE "C" NOT NULL PRIMARY KEY, expires_at BIGINT NOT NULL)`,
				`CREATE INDEX IF NOT EXISTS "replay_expires_idx" ON "auth"."replay" (expires_at)`,
			},
			`INSERT INTO "auth"."replay" (id, expires_at) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET expires_at = excluded.expires_at WHERE "replay".expires_at <= $3`},
		"sqlite": {SQLite, "main.replay",
			[]string{
				`CREATE TABLE IF NOT EXISTS "main"."replay" (id TEXT NOT NULL PRIMARY KEY, expires_at INTEGER NOT NULL) WITHOUT ROWID`,
				`CREATE INDEX IF NOT EXISTS "main"."replay_expires_idx" ON "replay" (expires_at)`,
			},
			`INSERT INTO "main"."replay" (id, expires_at) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET expires_at = excluded.expires_at WHERE "replay".expires_at <= ?`},
	} {
		t.Run(name, func(t *testing.T) {
			c, f := newFake(t, tc.dialect, WithTable(tc.table))
			if got := c.CreateTableStatements(); strings.Join(got, "\n") != strings.Join(tc.create, "\n") {
				t.Fatalf("CreateTableStatements =\n%s", strings.Join(got, "\n"))
			}
			if err := c.CreateTable(context.Background()); err != nil {
				t.Fatal(err)
			}
			c.Add(context.Background(), "a", time.Minute)
			if got := f.queries[len(f.queries)-1]; got != tc.add {
				t.Fatalf("add statement =\n%s", got)
			}
		})
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	db := sql.OpenDB(&fakeDB{})
	defer db.Close()
	if _, err := New(nil, PostgreSQL); err == nil {
		t.Error("nil db accepted")
	}
	for _, d := range []Dialect{0, 3} {
		if _, err := New(db, d); err == nil {
			t.Errorf("dialect %v accepted", d)
		}
	}
	for _, name := range []string{"", "a.b.c", `x"y`, "1abc", "a b", "a;DROP", ".a", "a.", strings.Repeat("a", 64)} {
		if _, err := New(db, PostgreSQL, WithTable(name)); err == nil {
			t.Errorf("table %q accepted", name)
		}
	}
	if _, err := New(db, PostgreSQL, WithTable("s."+strings.Repeat("a", 63))); err != nil {
		t.Errorf("63-byte table name rejected: %v", err)
	}
}
