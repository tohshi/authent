package rebac_test

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

	"github.com/tohshi/authent/rebac"
	"github.com/tohshi/authent/rebac/rebactest"
)

// fakeDB is an in-memory database/sql driver that understands exactly the
// statements SQLStore generates. It checks the dialect's placeholder style
// and lets tests inject failures and rows. Real databases are exercised by
// running rebactest.TestTupleStore against them.
type fakeDB struct {
	dialect rebac.SQLDialect
	// foldCase makes WHERE clauses compare case-insensitively, like a
	// table created with a case-insensitive collation.
	foldCase bool

	mu      sync.Mutex
	created bool
	rows    map[[6]string]bool
	// fail, if set, is called with each statement (and "COMMIT") and may
	// return an error to fail it.
	fail func(query string) error
}

func newFakeDB(t *testing.T, d rebac.SQLDialect) (*fakeDB, *sql.DB) {
	f := &fakeDB{dialect: d, rows: map[[6]string]bool{}}
	db := sql.OpenDB(f)
	// One connection proves that recursive reads do not need two.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return f, db
}

func newFakeStore(t *testing.T, d rebac.SQLDialect) (*fakeDB, *rebac.SQLStore) {
	f, db := newFakeDB(t, d)
	s, err := rebac.NewSQLStore(db, d)
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

var columns = []string{"object_type", "object_id", "relation", "subject_type", "subject_id", "subject_relation"}

func columnIndex(name string) int {
	for i, c := range columns {
		if c == name {
			return i
		}
	}
	return -1
}

func (f *fakeDB) insert(row [6]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[row] = true
}

type cond struct {
	col int
	val string
}

func (f *fakeDB) match(row [6]string, conds []cond) bool {
	for _, c := range conds {
		if f.foldCase && !strings.EqualFold(row[c.col], c.val) || !f.foldCase && row[c.col] != c.val {
			return false
		}
	}
	return true
}

type fakeOp struct {
	insert bool
	row    [6]string
	conds  []cond
}

func (f *fakeDB) apply(ops []fakeOp) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, op := range ops {
		if op.insert {
			f.rows[op.row] = true
			continue
		}
		for row := range f.rows {
			if f.match(row, op.conds) {
				delete(f.rows, row)
			}
		}
	}
}

var (
	condRE        = regexp.MustCompile(`(\w+) = (\$\d+|\?)`)
	placeholderRE = regexp.MustCompile(`\$\d+|\?`)
	tableRE       = regexp.MustCompile(`^(?:INSERT INTO|DELETE FROM|SELECT .* FROM) (\S+)`)
)

// parse checks the statement's placeholders and table, and maps WHERE
// conditions to their arguments.
func (f *fakeDB) parse(query string, args []driver.NamedValue) ([]cond, error) {
	if m := tableRE.FindStringSubmatch(query); m == nil || strings.Trim(m[1], "\"`") != rebac.DefaultSQLTable {
		return nil, fmt.Errorf("fake: unexpected table in %q", query)
	}
	phs := placeholderRE.FindAllString(query, -1)
	if len(phs) != len(args) {
		return nil, fmt.Errorf("fake: %d placeholders, %d args", len(phs), len(args))
	}
	for i, p := range phs {
		if want := map[bool]string{true: "$" + strconv.Itoa(i+1), false: "?"}[f.dialect == rebac.PostgreSQL]; p != want {
			return nil, fmt.Errorf("fake: placeholder %s, want %s", p, want)
		}
	}
	var conds []cond
	for i, m := range condRE.FindAllStringSubmatch(query, -1) {
		col := columnIndex(m[1])
		if col < 0 {
			return nil, fmt.Errorf("fake: unknown column %q", m[1])
		}
		conds = append(conds, cond{col, args[i].Value.(string)})
	}
	return conds, nil
}

type fakeConn struct {
	db *fakeDB
	tx *fakeTx
}

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) { return &fakeStmt{c, query}, nil }
func (c *fakeConn) Close() error                              { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *fakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.tx = &fakeTx{conn: c}
	return c.tx, nil
}

func (c *fakeConn) check(query string) error {
	c.db.mu.Lock()
	fail := c.db.fail
	created := c.db.created
	c.db.mu.Unlock()
	if fail != nil {
		if err := fail(query); err != nil {
			return err
		}
	}
	if !created && !strings.HasPrefix(query, "CREATE ") {
		return errors.New("fake: no such table")
	}
	return nil
}

func (c *fakeConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.check(query); err != nil {
		return nil, err
	}
	var op fakeOp
	switch {
	case strings.HasPrefix(query, "CREATE "):
		c.db.mu.Lock()
		c.db.created = true
		c.db.mu.Unlock()
		return driver.RowsAffected(0), nil
	case strings.HasPrefix(query, "INSERT INTO "):
		if !strings.HasSuffix(query, " ON CONFLICT DO NOTHING") && !strings.HasSuffix(query, " ON DUPLICATE KEY UPDATE object_type = object_type") {
			return nil, fmt.Errorf("fake: insert without conflict handling: %q", query)
		}
		if _, err := c.db.parse(query, args); err != nil {
			return nil, err
		}
		if len(args) != 6 {
			return nil, fmt.Errorf("fake: insert with %d args", len(args))
		}
		op.insert = true
		for i, a := range args {
			op.row[i] = a.Value.(string)
		}
	case strings.HasPrefix(query, "DELETE FROM "):
		conds, err := c.db.parse(query, args)
		if err != nil {
			return nil, err
		}
		if len(conds) != 6 {
			return nil, fmt.Errorf("fake: delete with %d conditions", len(conds))
		}
		op.conds = conds
	default:
		return nil, fmt.Errorf("fake: unsupported exec %q", query)
	}
	if c.tx == nil {
		return nil, errors.New("fake: write outside a transaction")
	}
	c.tx.ops = append(c.tx.ops, op)
	return driver.RowsAffected(1), nil
}

func (c *fakeConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.check(query); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(query, "SELECT "+strings.Join(columns, ", ")+" FROM ") {
		return nil, fmt.Errorf("fake: unsupported query %q", query)
	}
	conds, err := c.db.parse(query, args)
	if err != nil {
		return nil, err
	}
	c.db.mu.Lock()
	defer c.db.mu.Unlock()
	r := &fakeRows{bytes: c.db.dialect == rebac.MySQL}
	for row := range c.db.rows {
		if c.db.match(row, conds) {
			r.rows = append(r.rows, row)
		}
	}
	return r, nil
}

type fakeTx struct {
	conn *fakeConn
	ops  []fakeOp
}

func (tx *fakeTx) Commit() error {
	tx.conn.tx = nil
	if err := tx.conn.check("COMMIT"); err != nil {
		return err
	}
	tx.conn.db.apply(tx.ops)
	return nil
}

func (tx *fakeTx) Rollback() error {
	tx.conn.tx = nil
	return nil
}

type fakeStmt struct {
	conn  *fakeConn
	query string
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }

func (s *fakeStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), named(args))
}

func (s *fakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), named(args))
}

func (s *fakeStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.conn.ExecContext(ctx, s.query, args)
}

func (s *fakeStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.conn.QueryContext(ctx, s.query, args)
}

func named(args []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(args))
	for i, a := range args {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: a}
	}
	return out
}

type fakeRows struct {
	rows  [][6]string
	bytes bool // return []byte, like VARBINARY columns
}

func (r *fakeRows) Columns() []string { return columns }
func (r *fakeRows) Close() error      { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	for i, v := range r.rows[0] {
		if r.bytes {
			dest[i] = []byte(v)
		} else {
			dest[i] = v
		}
	}
	r.rows = r.rows[1:]
	return nil
}

var dialects = []rebac.SQLDialect{rebac.PostgreSQL, rebac.MySQL, rebac.SQLite}

func TestSQLStoreConformance(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.String(), func(t *testing.T) {
			rebactest.TestTupleStore(t, func(t *testing.T) rebac.TupleStore {
				_, s := newFakeStore(t, d)
				return s
			})
		})
	}
}

var errFake = errors.New("fake failure")

func readAll(s rebac.TupleStore, f rebac.Filter) ([]rebac.Tuple, error) {
	var out []rebac.Tuple
	for tp, err := range s.Read(context.Background(), f) {
		if err != nil {
			return out, err
		}
		out = append(out, tp)
	}
	return out, nil
}

func TestSQLStoreWriteIsAtomic(t *testing.T) {
	ctx := context.Background()
	for _, failOn := range []string{"INSERT", "COMMIT"} {
		t.Run(failOn, func(t *testing.T) {
			f, s := newFakeStore(t, rebac.PostgreSQL)
			old := rebac.MustParseTuple("doc:a#viewer@user:old")
			if err := s.Write(ctx, []rebac.Tuple{old}, nil); err != nil {
				t.Fatal(err)
			}
			inserts := 0
			f.fail = func(q string) error {
				if strings.HasPrefix(q, "INSERT") {
					inserts++
				}
				if failOn == "INSERT" && inserts == 2 || failOn == "COMMIT" && q == "COMMIT" {
					return errFake
				}
				return nil
			}
			err := s.Write(ctx,
				[]rebac.Tuple{rebac.MustParseTuple("doc:a#viewer@user:x"), rebac.MustParseTuple("doc:a#viewer@user:y")},
				[]rebac.Tuple{old})
			if !errors.Is(err, errFake) {
				t.Fatalf("Write error = %v, want %v", err, errFake)
			}
			f.fail = nil
			got, err := readAll(s, rebac.Filter{})
			if err != nil || len(got) != 1 || got[0] != old {
				t.Fatalf("after failed write: %v, %v; want only %s", got, err, old)
			}
		})
	}
}

func TestSQLStoreErrorsFailClosed(t *testing.T) {
	f, s := newFakeStore(t, rebac.SQLite)
	schema, err := rebac.NewSchema(rebac.Type("user"), rebac.Type("doc", rebac.Relation("viewer", rebac.Direct("user"))))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := rebac.NewEngine(schema, s)
	ctx := context.Background()
	if err := e.Write(ctx, []rebac.Tuple{rebac.MustParseTuple("doc:a#viewer@user:alice")}, nil); err != nil {
		t.Fatal(err)
	}
	f.fail = func(q string) error {
		if strings.HasPrefix(q, "SELECT") {
			return errFake
		}
		return nil
	}
	ok, err := e.Check(ctx, rebac.Obj("doc", "a"), "viewer", rebac.Sub("user", "alice"))
	if ok || !errors.Is(err, errFake) {
		t.Fatalf("Check = %v, %v; want false, %v", ok, err, errFake)
	}
}

func TestSQLStoreRejectsInvalidRows(t *testing.T) {
	for _, row := range [][6]string{
		{"doc", "*", "viewer", "user", "alice", ""},     // wildcard object
		{"doc", "a", "Viewer", "user", "alice", ""},     // invalid relation name
		{"doc", "a", "viewer", "user", "*", "member"},   // wildcard userset
		{"doc", "a", "viewer", "user", "al ice", ""},    // space in ID
		{"doc", "a", "viewer", "user", "", ""},          // empty ID
		{"doc", "a", "viewer", "user", "a\x00lice", ""}, // control character
	} {
		f, s := newFakeStore(t, rebac.MySQL)
		f.insert(row)
		_, err := readAll(s, rebac.Filter{ObjectType: "doc", ObjectID: row[1], Relation: row[2]})
		if !errors.Is(err, rebac.ErrInvalidTuple) {
			t.Errorf("Read of row %q: err = %v, want ErrInvalidTuple", row, err)
		}
		// The invalid row can be deleted.
		bad := rebac.Tuple{
			Object:   rebac.Obj(row[0], row[1]),
			Relation: row[2],
			Subject:  rebac.Subject{Object: rebac.Obj(row[3], row[4]), Relation: row[5]},
		}
		if err := s.Write(context.Background(), nil, []rebac.Tuple{bad}); err != nil {
			t.Fatal(err)
		}
		if got, err := readAll(s, rebac.Filter{}); err != nil || len(got) != 0 {
			t.Errorf("after deleting %q: %v, %v", row, got, err)
		}
	}
}

func TestSQLStoreRejectsInvalidWrites(t *testing.T) {
	_, s := newFakeStore(t, rebac.PostgreSQL)
	good := rebac.MustParseTuple("doc:a#viewer@user:alice")
	bad := rebac.Tuple{Object: rebac.Obj("doc", "*"), Relation: "viewer", Subject: rebac.Sub("user", "bob")}
	if err := s.Write(context.Background(), []rebac.Tuple{good, bad}, nil); !errors.Is(err, rebac.ErrInvalidTuple) {
		t.Fatalf("Write err = %v, want ErrInvalidTuple", err)
	}
	if got, err := readAll(s, rebac.Filter{}); err != nil || len(got) != 0 {
		t.Fatalf("after rejected write: %v, %v", got, err)
	}
}

func TestSQLStoreDiscardsInexactRows(t *testing.T) {
	// A table with a case-insensitive collation returns rows for other IDs.
	// They must not grant access.
	f, s := newFakeStore(t, rebac.MySQL)
	f.foldCase = true
	f.insert([6]string{"doc", "README", "viewer", "user", "eve", ""})
	f.insert([6]string{"doc", "readme", "viewer", "user", "Eve", ""})
	schema, err := rebac.NewSchema(rebac.Type("user"), rebac.Type("doc", rebac.Relation("viewer", rebac.Direct("user"))))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := rebac.NewEngine(schema, s)
	ok, err := e.Check(context.Background(), rebac.Obj("doc", "readme"), "viewer", rebac.Sub("user", "eve"))
	if ok || err != nil {
		t.Fatalf("Check = %v, %v; want false, nil", ok, err)
	}
	eve := rebac.Sub("user", "eve")
	got, err := readAll(s, rebac.Filter{Subject: &eve})
	if err != nil || len(got) != 1 || got[0].Object.ID != "README" {
		t.Fatalf("reverse read = %v, %v", got, err)
	}
}

func TestSQLStoreRequiresTable(t *testing.T) {
	_, db := newFakeDB(t, rebac.SQLite)
	s, err := rebac.NewSQLStore(db, rebac.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAll(s, rebac.Filter{}); err == nil {
		t.Fatal("Read before CreateTable succeeded")
	}
	ctx := context.Background()
	for range 2 { // idempotent
		if err := s.CreateTable(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := readAll(s, rebac.Filter{}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreCreateTableStatements(t *testing.T) {
	_, db := newFakeDB(t, rebac.PostgreSQL)
	for _, d := range dialects {
		s, err := rebac.NewSQLStore(db, d, rebac.WithSQLTable("authz.tuples"))
		if err != nil {
			t.Fatal(err)
		}
		stmts := s.CreateTableStatements()
		if len(stmts) == 0 || !strings.HasPrefix(stmts[0], "CREATE TABLE IF NOT EXISTS ") || !strings.Contains(stmts[0], "authz") {
			t.Errorf("%v: CreateTableStatements() = %q", d, stmts)
		}
		stmts[0] = "mutated"
		if s.CreateTableStatements()[0] == "mutated" {
			t.Errorf("%v: CreateTableStatements returned internal state", d)
		}
	}
}

func TestNewSQLStore(t *testing.T) {
	_, db := newFakeDB(t, rebac.PostgreSQL)
	if _, err := rebac.NewSQLStore(nil, rebac.PostgreSQL); err == nil {
		t.Error("nil db accepted")
	}
	for _, d := range []rebac.SQLDialect{0, 4} {
		if _, err := rebac.NewSQLStore(db, d); err == nil {
			t.Errorf("dialect %v accepted", d)
		}
	}
	for _, name := range []string{"tuples", "_t1", "authz.tuples", "A_B.c9", strings.Repeat("t", 63)} {
		if _, err := rebac.NewSQLStore(db, rebac.PostgreSQL, rebac.WithSQLTable(name)); err != nil {
			t.Errorf("table %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{
		"", ".", "a.", ".a", "a.b.c", "1abc", "a-b", "a b", `a"b`, "a`b", "a;DROP TABLE x",
		"tuples\x00", "té", strings.Repeat("t", 64),
	} {
		if _, err := rebac.NewSQLStore(db, rebac.PostgreSQL, rebac.WithSQLTable(name)); err == nil {
			t.Errorf("table %q accepted", name)
		}
	}
}
