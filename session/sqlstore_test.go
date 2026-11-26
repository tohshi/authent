package session_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/session"
	"github.com/tohshi/authent/session/sessiontest"
)

// fakeDB is an in-memory database/sql driver that understands exactly the
// statements SQLStore generates. It checks the dialect's placeholder style
// and lets tests inject failures and rows. Real databases are exercised by
// running sessiontest.TestStore against them.
type fakeDB struct {
	dialect session.SQLDialect
	// foldCase makes WHERE clauses compare text case-insensitively, like a
	// table created with a case-insensitive collation.
	foldCase bool

	mu      sync.Mutex
	created bool
	rows    map[string]fakeRow // by token_hash
	// fail, if set, is called with each statement and may return an error
	// to fail it.
	fail func(query string) error
}

type fakeRow struct {
	subject          string
	version, expires int64
	data             []byte
}

func newFakeDB(t *testing.T, d session.SQLDialect) (*fakeDB, *sql.DB) {
	f := &fakeDB{dialect: d, rows: map[string]fakeRow{}}
	db := sql.OpenDB(f)
	t.Cleanup(func() { db.Close() })
	return f, db
}

func newFakeStore(t *testing.T, d session.SQLDialect) (*fakeDB, *session.SQLStore) {
	f, db := newFakeDB(t, d)
	s, err := session.NewSQLStore(db, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTable(context.Background()); err != nil {
		t.Fatal(err)
	}
	return f, s
}

func (f *fakeDB) Connect(context.Context) (driver.Conn, error) { return &fakeConn{db: f}, nil }
func (f *fakeDB) Driver() driver.Driver                        { return fakeDriver{} }

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use sql.OpenDB") }

func (f *fakeDB) setFail(fn func(string) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fn
}

func (f *fakeDB) len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows)
}

func (f *fakeDB) insert(key string, r fakeRow) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[key] = r
}

var (
	termRE        = regexp.MustCompile(`(\w+) (=|>|<=) (\$\d+|\?)`)
	placeholderRE = regexp.MustCompile(`\$\d+|\?`)
	tableRE       = regexp.MustCompile(`^(?:INSERT INTO|UPDATE|DELETE FROM|SELECT .* FROM) (\S+)`)
	selectPrefix  = "SELECT token_hash, subject, version, expires_at, data FROM "
	insertCols    = "(token_hash, subject, version, expires_at, data) VALUES "
)

// term is one "column op placeholder" of a SET or WHERE clause.
type term struct {
	col, op string
	val     any
	where   bool
}

// parse checks the statement's table and placeholders and returns its
// terms with their arguments.
func (f *fakeDB) parse(query string, args []driver.NamedValue) ([]term, error) {
	if m := tableRE.FindStringSubmatch(query); m == nil || strings.Trim(m[1], "\"`") != session.DefaultSQLTable {
		return nil, fmt.Errorf("fake: unexpected table in %q", query)
	}
	phs := placeholderRE.FindAllString(query, -1)
	if len(phs) != len(args) {
		return nil, fmt.Errorf("fake: %d placeholders, %d args in %q", len(phs), len(args), query)
	}
	for i, p := range phs {
		want := "?"
		if f.dialect == session.PostgreSQL {
			want = "$" + strconv.Itoa(i+1)
		}
		if p != want {
			return nil, fmt.Errorf("fake: placeholder %s, want %s", p, want)
		}
	}
	where := strings.Index(query, " WHERE ")
	var terms []term
	for i, m := range termRE.FindAllStringSubmatchIndex(query, -1) {
		terms = append(terms, term{
			col:   query[m[2]:m[3]],
			op:    query[m[4]:m[5]],
			val:   args[i].Value,
			where: where >= 0 && m[0] > where,
		})
	}
	return terms, nil
}

func (f *fakeDB) match(key string, r fakeRow, terms []term) (bool, error) {
	for _, t := range terms {
		if !t.where {
			continue
		}
		var ok bool
		switch t.col {
		case "token_hash", "subject":
			got := key
			if t.col == "subject" {
				got = r.subject
			}
			want, _ := t.val.(string)
			ok = t.op == "=" && (got == want || f.foldCase && strings.EqualFold(got, want))
		case "version", "expires_at":
			got := r.version
			if t.col == "expires_at" {
				got = r.expires
			}
			want, isInt := t.val.(int64)
			if !isInt {
				return false, fmt.Errorf("fake: %s compared with %T", t.col, t.val)
			}
			ok = t.op == "=" && got == want || t.op == ">" && got > want || t.op == "<=" && got <= want
		default:
			return false, fmt.Errorf("fake: unknown column %q", t.col)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

type fakeConn struct{ db *fakeDB }

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) { return &fakeStmt{c, query}, nil }
func (c *fakeConn) Close() error                              { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)                 { return nil, errors.New("fake: no transactions") }

func (c *fakeConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	f := c.db
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		if err := f.fail(query); err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(query, "CREATE ") {
		f.created = true
		return driver.RowsAffected(0), nil
	}
	if !f.created {
		return nil, errors.New("fake: no such table")
	}
	terms, err := f.parse(query, args)
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasPrefix(query, "INSERT INTO ") && strings.Contains(query, insertCols):
		key, _ := args[0].Value.(string)
		if _, dup := f.rows[key]; dup {
			return nil, errors.New("fake: duplicate key value violates unique constraint")
		}
		subject, _ := args[1].Value.(string)
		version, _ := args[2].Value.(int64)
		expires, _ := args[3].Value.(int64)
		data, _ := args[4].Value.([]byte)
		f.rows[key] = fakeRow{subject, version, expires, append([]byte(nil), data...)}
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(query, "UPDATE "), strings.HasPrefix(query, "DELETE FROM "):
		var n int64
		for key, r := range f.rows {
			ok, err := f.match(key, r, terms)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			n++
			if strings.HasPrefix(query, "DELETE ") {
				delete(f.rows, key)
				continue
			}
			for _, t := range terms {
				switch {
				case t.where:
				case t.col == "version":
					r.version = t.val.(int64)
				case t.col == "expires_at":
					r.expires = t.val.(int64)
				case t.col == "data":
					r.data = append([]byte(nil), t.val.([]byte)...)
				default:
					return nil, fmt.Errorf("fake: unexpected SET %s", t.col)
				}
			}
			f.rows[key] = r
		}
		return driver.RowsAffected(n), nil
	}
	return nil, fmt.Errorf("fake: unsupported exec %q", query)
}

func (c *fakeConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	f := c.db
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		if err := f.fail(query); err != nil {
			return nil, err
		}
	}
	if !f.created {
		return nil, errors.New("fake: no such table")
	}
	if !strings.HasPrefix(query, selectPrefix) {
		return nil, fmt.Errorf("fake: unsupported query %q", query)
	}
	terms, err := f.parse(query, args)
	if err != nil {
		return nil, err
	}
	rows := &fakeRows{bytes: f.dialect == session.MySQL}
	for key, r := range f.rows {
		ok, err := f.match(key, r, terms)
		if err != nil {
			return nil, err
		}
		if ok {
			rows.keys = append(rows.keys, key)
			rows.rows = append(rows.rows, r)
		}
	}
	return rows, nil
}

type fakeStmt struct {
	conn  *fakeConn
	query string
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }

func (s *fakeStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.conn.ExecContext(context.Background(), s.query, named(args))
}

func (s *fakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.conn.QueryContext(context.Background(), s.query, named(args))
}

func named(args []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(args))
	for i, a := range args {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: a}
	}
	return out
}

type fakeRows struct {
	keys  []string
	rows  []fakeRow
	bytes bool // return text as []byte, like VARBINARY columns
}

func (r *fakeRows) Columns() []string {
	return []string{"token_hash", "subject", "version", "expires_at", "data"}
}
func (r *fakeRows) Close() error { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	key, row := r.keys[0], r.rows[0]
	r.keys, r.rows = r.keys[1:], r.rows[1:]
	dest[0], dest[1] = key, row.subject
	if r.bytes {
		dest[0], dest[1] = []byte(key), []byte(row.subject)
	}
	dest[2], dest[3], dest[4] = row.version, row.expires, append([]byte(nil), row.data...)
	return nil
}

var dialects = []session.SQLDialect{session.PostgreSQL, session.MySQL, session.SQLite}

func TestSQLStoreConformance(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.String(), func(t *testing.T) {
			sessiontest.TestStore(t, func(t *testing.T) session.Store {
				_, s := newFakeStore(t, d)
				return s
			})
		})
	}
}

var (
	ctx     = context.Background()
	errFake = errors.New("fake failure")
)

func record(subject string, version uint64, expires time.Time) session.Record {
	return session.Record{Subject: subject, Version: version, ExpiresAt: expires, Data: []byte("{}")}
}

func TestSQLStoreDeleteExpired(t *testing.T) {
	f, s := newFakeStore(t, session.SQLite)
	live, dead := "live", "dead"
	if err := s.Save(ctx, live, record("alice", 1, time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, dead, record("alice", 1, time.Now().Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	if f.len() != 2 {
		t.Fatalf("%d rows before DeleteExpired, want 2", f.len())
	}
	if err := s.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if f.len() != 1 {
		t.Fatalf("%d rows after DeleteExpired, want 1", f.len())
	}
	if _, err := s.Load(ctx, live); err != nil {
		t.Fatalf("DeleteExpired removed a live session: %v", err)
	}
}

func TestSQLStoreDiscardsInexactRows(t *testing.T) {
	// A table with a case-insensitive collation returns rows for other
	// keys and subjects. They must not be loaded or listed.
	f, s := newFakeStore(t, session.MySQL)
	f.foldCase = true
	exp := time.Now().Add(time.Hour).UnixNano()
	f.insert("KEY", fakeRow{"Alice", 1, exp, []byte("{}")})
	if _, err := s.Load(ctx, "key"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("Load of a key differing in case: err = %v, want ErrNotFound", err)
	}
	if got, err := s.List(ctx, "alice"); err != nil || len(got) != 0 {
		t.Fatalf("List(alice) = %v, %v; want only exact subjects", got, err)
	}
	if got, err := s.List(ctx, "Alice"); err != nil || len(got) != 1 {
		t.Fatalf("List(Alice) = %v, %v", got, err)
	}
}

func TestSQLStoreErrorsFailClosed(t *testing.T) {
	f, s := newFakeStore(t, session.PostgreSQL)
	m, err := session.NewManager(s)
	if err != nil {
		t.Fatal(err)
	}
	token, s1, err := m.Create(ctx, authent.Principal{Subject: "alice", Method: authent.MethodPassword})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		failOn string
		calls  map[string]func() error
	}{
		{"SELECT", map[string]func() error{
			"Get":    func() error { _, err := m.Get(ctx, token); return err },
			"List":   func() error { _, err := m.List(ctx, "alice"); return err },
			"Revoke": func() error { return m.Revoke(ctx, "alice", s1.Handle()) },
		}},
		{"UPDATE", map[string]func() error{
			"Save": func() error { return m.Save(ctx, s1) },
		}},
		{"DELETE", map[string]func() error{
			"Destroy":   func() error { return m.Destroy(ctx, token) },
			"RevokeAll": func() error { return m.RevokeAll(ctx, "alice") },
			"Rotate":    func() error { _, _, err := m.Rotate(ctx, token); return err },
		}},
		{"INSERT", map[string]func() error{
			"Create": func() error {
				_, _, err := m.Create(ctx, authent.Principal{Subject: "bob", Method: authent.MethodPassword})
				return err
			},
		}},
	} {
		f.setFail(func(q string) error {
			if strings.HasPrefix(q, tc.failOn) {
				return errFake
			}
			return nil
		})
		for name, call := range tc.calls {
			err := call()
			if !errors.Is(err, errFake) || errors.Is(err, authent.ErrUnauthenticated) || errors.Is(err, session.ErrConflict) {
				t.Errorf("%s with a failing %s: err = %v, want the database error", name, tc.failOn, err)
			}
		}
	}
	f.setFail(nil)
	if _, err := m.Get(ctx, token); err != nil {
		t.Fatalf("Get after the failures: %v", err)
	}
}

func TestSQLStoreRejectsLongSubject(t *testing.T) {
	_, s := newFakeStore(t, session.MySQL)
	long := strings.Repeat("a", 1025)
	if err := s.Save(ctx, "k", record(long, 1, time.Now().Add(time.Hour))); err == nil || errors.Is(err, session.ErrConflict) {
		t.Fatalf("Save with a 1025-byte subject: err = %v", err)
	}
	if err := s.Save(ctx, "k", record(long[:1024], 1, time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("Save with a 1024-byte subject: %v", err)
	}
}

func TestSQLStoreRequiresTable(t *testing.T) {
	_, db := newFakeDB(t, session.SQLite)
	s, err := session.NewSQLStore(db, session.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, "k"); err == nil || errors.Is(err, session.ErrNotFound) {
		t.Fatalf("Load before CreateTable: err = %v, want a database error", err)
	}
	for range 2 { // idempotent
		if err := s.CreateTable(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Load(ctx, "k"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("Load after CreateTable: err = %v", err)
	}
}

func TestSQLStoreCreateTableStatements(t *testing.T) {
	_, db := newFakeDB(t, session.PostgreSQL)
	for _, d := range dialects {
		s, err := session.NewSQLStore(db, d, session.WithSQLTable("auth.sessions"))
		if err != nil {
			t.Fatal(err)
		}
		stmts := s.CreateTableStatements()
		if len(stmts) == 0 || !strings.HasPrefix(stmts[0], "CREATE TABLE IF NOT EXISTS ") || !strings.Contains(stmts[0], "auth") {
			t.Errorf("%v: CreateTableStatements() = %q", d, stmts)
		}
		stmts[0] = "mutated"
		if s.CreateTableStatements()[0] == "mutated" {
			t.Errorf("%v: CreateTableStatements returned internal state", d)
		}
	}
}

func TestNewSQLStore(t *testing.T) {
	_, db := newFakeDB(t, session.PostgreSQL)
	if _, err := session.NewSQLStore(nil, session.PostgreSQL); err == nil {
		t.Error("nil db accepted")
	}
	for _, d := range []session.SQLDialect{0, 4} {
		if _, err := session.NewSQLStore(db, d); err == nil {
			t.Errorf("dialect %v accepted", d)
		}
	}
	for _, name := range []string{"sessions", "_t1", "auth.sessions", "A_B.c9", strings.Repeat("t", 51), strings.Repeat("s", 63) + ".t"} {
		if _, err := session.NewSQLStore(db, session.PostgreSQL, session.WithSQLTable(name)); err != nil {
			t.Errorf("table %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{
		"", ".", "a.", ".a", "a.b.c", "1abc", "a-b", "a b", `a"b`, "a`b", "a;DROP TABLE x",
		"sessions\x00", "té", strings.Repeat("t", 52), strings.Repeat("s", 64) + ".t",
	} {
		if _, err := session.NewSQLStore(db, session.PostgreSQL, session.WithSQLTable(name)); err == nil {
			t.Errorf("table %q accepted", name)
		}
	}
}
