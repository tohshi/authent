package rebac_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/tohshi/authent/rebac"
	"github.com/tohshi/authent/rebac/rebactest"
)

// fakeDB is an in-memory database/sql driver that understands exactly the
// statements SQLStore generates. It checks the dialect's placeholder style,
// serializes transactions over a working copy of the data, and lets tests
// inject failures and rows. Real databases are exercised by running
// rebactest.TestTupleStore against them.
type fakeDB struct {
	dialect rebac.SQLDialect
	// foldCase makes tuple column conditions compare case-insensitively,
	// like a table created with a case-insensitive collation.
	foldCase bool

	txMu    sync.Mutex // held by the open transaction
	mu      sync.Mutex
	created bool
	data    fakeData
	// fail, if set, is called with each statement (and "COMMIT") and may
	// return an error to fail it.
	fail func(query string) error
}

type fakeData struct {
	seeded      bool
	rev, pruned int64
	rows        []fakeRow
}

type fakeRow struct {
	cols             [6]string
	caveat           [2]string
	created, deleted int64
}

func (d fakeData) clone() fakeData {
	d.rows = slices.Clone(d.rows)
	return d
}

func newFakeDB(t *testing.T, d rebac.SQLDialect) (*fakeDB, *sql.DB) {
	f := &fakeDB{dialect: d}
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

// insert adds a row that is present at every revision.
func (f *fakeDB) insert(cols [6]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data.rows = append(f.data.rows, fakeRow{cols: cols, deleted: math.MaxInt64})
}

func (f *fakeDB) Connect(context.Context) (driver.Conn, error) { return &fakeConn{db: f}, nil }
func (f *fakeDB) Driver() driver.Driver                        { return fakeDriver{} }

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use sql.OpenDB") }

var columns = []string{"object_type", "object_id", "relation", "subject_type", "subject_id", "subject_relation"}

var (
	condRE        = regexp.MustCompile(`(?:t\.)?(\w+) (=|<=|<|>) (\$\d+|\?)`)
	placeholderRE = regexp.MustCompile(`\$\d+|\?`)
	tableRE       = regexp.MustCompile(`(?:^INSERT INTO|^DELETE FROM|^UPDATE| FROM| JOIN) (\S+)`)
)

type cond struct {
	col string
	op  string
	val any
}

// parse checks the statement's placeholders and tables, and maps its
// conditions to their arguments.
func (f *fakeDB) parse(query string, args []driver.NamedValue) ([]cond, error) {
	for _, m := range tableRE.FindAllStringSubmatch(query, -1) {
		name := strings.Trim(m[1], "\"`")
		if name != rebac.DefaultSQLTable && name != rebac.DefaultSQLTable+"_revision" {
			return nil, fmt.Errorf("fake: unexpected table %q in %q", name, query)
		}
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
	where, offset := query, 0
	if strings.HasPrefix(query, "UPDATE") {
		i := strings.Index(query, " WHERE ")
		where, offset = query[i:], len(placeholderRE.FindAllString(query[:i], -1))
	}
	var conds []cond
	for k, m := range condRE.FindAllStringSubmatch(where, -1) {
		conds = append(conds, cond{m[1], m[2], args[offset+k].Value})
	}
	return conds, nil
}

func (f *fakeDB) match(r fakeRow, conds []cond) bool {
	for _, c := range conds {
		switch c.col {
		case "created_rev", "deleted_rev":
			v := r.created
			if c.col == "deleted_rev" {
				v = r.deleted
			}
			arg := c.val.(int64)
			if !map[string]bool{"=": v == arg, "<=": v <= arg, "<": v < arg, ">": v > arg}[c.op] {
				return false
			}
		default:
			i := slices.Index(columns, c.col)
			if i < 0 {
				return false
			}
			v, arg := r.cols[i], c.val.(string)
			if f.foldCase && !strings.EqualFold(v, arg) || !f.foldCase && v != arg {
				return false
			}
		}
	}
	return true
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
	c.db.txMu.Lock()
	c.db.mu.Lock()
	c.tx = &fakeTx{conn: c, data: c.db.data.clone()}
	c.db.mu.Unlock()
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

// view runs fn on the transaction's data, or on the committed data.
func (c *fakeConn) view(fn func(*fakeData)) {
	if c.tx != nil {
		fn(&c.tx.data)
		return
	}
	c.db.mu.Lock()
	defer c.db.mu.Unlock()
	fn(&c.db.data)
}

func (c *fakeConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.check(query); err != nil {
		return nil, err
	}
	if strings.HasPrefix(query, "CREATE ") {
		c.db.mu.Lock()
		c.db.created = true
		c.db.mu.Unlock()
		return driver.RowsAffected(0), nil
	}
	conds, err := c.db.parse(query, args)
	if err != nil {
		return nil, err
	}
	revTable := strings.Contains(query, "_revision")
	if !strings.HasPrefix(query, "INSERT") || !revTable {
		if c.tx == nil {
			return nil, errors.New("fake: write outside a transaction")
		}
	}
	var n int64
	switch {
	case strings.HasPrefix(query, "INSERT") && revTable:
		if !strings.HasSuffix(query, " ON CONFLICT DO NOTHING") && !strings.HasSuffix(query, " ON DUPLICATE KEY UPDATE id = id") {
			return nil, fmt.Errorf("fake: insert without conflict handling: %q", query)
		}
		c.view(func(d *fakeData) {
			if !d.seeded {
				d.seeded = true
				n = 1
			}
		})
	case strings.HasPrefix(query, "UPDATE") && strings.Contains(query, "SET rev = rev + 1"):
		c.view(func(d *fakeData) { d.rev++; n = 1 })
	case strings.HasPrefix(query, "UPDATE") && strings.Contains(query, "SET pruned_rev"):
		c.view(func(d *fakeData) {
			if v := args[0].Value.(int64); d.pruned < v {
				d.pruned = v
				n = 1
			}
		})
	case strings.HasPrefix(query, "INSERT"):
		if !strings.HasSuffix(query, " ON CONFLICT DO NOTHING") && !strings.HasSuffix(query, " ON DUPLICATE KEY UPDATE object_type = object_type") {
			return nil, fmt.Errorf("fake: insert without conflict handling: %q", query)
		}
		if len(args) != 10 {
			return nil, fmt.Errorf("fake: insert with %d args", len(args))
		}
		var r fakeRow
		for i := range r.cols {
			r.cols[i] = args[i].Value.(string)
		}
		r.caveat = [2]string{args[6].Value.(string), args[7].Value.(string)}
		r.created, r.deleted = args[8].Value.(int64), args[9].Value.(int64)
		c.view(func(d *fakeData) {
			if !slices.ContainsFunc(d.rows, func(o fakeRow) bool { return o.cols == r.cols && o.deleted == r.deleted }) {
				d.rows = append(d.rows, r)
				n = 1
			}
		})
	case strings.HasPrefix(query, "UPDATE"):
		if len(conds) != 7 {
			return nil, fmt.Errorf("fake: update with %d conditions", len(conds))
		}
		rev := args[0].Value.(int64)
		replace := strings.Contains(query, " AND (caveat_name <> ")
		if replace != (len(args) == 10) {
			return nil, fmt.Errorf("fake: update with %d args: %q", len(args), query)
		}
		c.view(func(d *fakeData) {
			for i, r := range d.rows {
				if replace && r.caveat == [2]string{args[8].Value.(string), args[9].Value.(string)} {
					continue
				}
				if c.db.match(r, conds) {
					d.rows[i].deleted = rev
					n++
				}
			}
		})
	case strings.HasPrefix(query, "DELETE"):
		c.view(func(d *fakeData) {
			d.rows = slices.DeleteFunc(d.rows, func(r fakeRow) bool {
				if c.db.match(r, conds) {
					n++
					return true
				}
				return false
			})
		})
	default:
		return nil, fmt.Errorf("fake: unsupported exec %q", query)
	}
	return driver.RowsAffected(n), nil
}

func (c *fakeConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.check(query); err != nil {
		return nil, err
	}
	conds, err := c.db.parse(query, args)
	if err != nil {
		return nil, err
	}
	r := &fakeRows{}
	switch {
	case strings.HasPrefix(query, "SELECT rev FROM "):
		r.cols = []string{"rev"}
		c.view(func(d *fakeData) {
			if d.seeded {
				r.rows = append(r.rows, []driver.Value{d.rev})
			}
		})
	case strings.HasPrefix(query, "SELECT r.rev, r.pruned_rev, t."+strings.Join(columns, ", t.")+", t.caveat_name, t.caveat_context"):
		changes := strings.Contains(query, ", t.created_rev, t.deleted_rev FROM")
		r.cols = append(append([]string{"rev", "pruned_rev"}, columns...), "caveat_name", "caveat_context")
		if changes {
			r.cols = append(r.cols, "created_rev", "deleted_rev")
			if len(args) != 3 || !strings.Contains(query, "(t.created_rev > ") {
				return nil, fmt.Errorf("fake: unsupported changes query %q", query)
			}
		}
		c.view(func(d *fakeData) {
			if !d.seeded {
				return
			}
			for _, row := range d.rows {
				ok := c.db.match(row, conds)
				if changes {
					after, before := args[0].Value.(int64), args[2].Value.(int64)
					ok = row.created > after || row.deleted > args[1].Value.(int64) && row.deleted < before
				}
				if !ok {
					continue
				}
				v := []driver.Value{d.rev, d.pruned}
				for _, col := range append(row.cols[:], row.caveat[:]...) {
					if c.db.dialect == rebac.MySQL {
						v = append(v, []byte(col))
					} else {
						v = append(v, col)
					}
				}
				if changes {
					v = append(v, row.created, row.deleted)
				}
				r.rows = append(r.rows, v)
			}
			if len(r.rows) == 0 {
				v := []driver.Value{d.rev, d.pruned}
				for range len(r.cols) - 2 {
					v = append(v, nil)
				}
				r.rows = append(r.rows, v)
			}
		})
	default:
		return nil, fmt.Errorf("fake: unsupported query %q", query)
	}
	return r, nil
}

type fakeTx struct {
	conn *fakeConn
	data fakeData
}

func (tx *fakeTx) Commit() error {
	defer tx.end()
	if err := tx.conn.check("COMMIT"); err != nil {
		return err
	}
	tx.conn.db.mu.Lock()
	tx.conn.db.data = tx.data
	tx.conn.db.mu.Unlock()
	return nil
}

func (tx *fakeTx) Rollback() error {
	tx.end()
	return nil
}

func (tx *fakeTx) end() {
	tx.conn.tx = nil
	tx.conn.db.txMu.Unlock()
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
	cols []string
	rows [][]driver.Value
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	copy(dest, r.rows[0])
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
	rev, err := s.Revision(context.Background())
	if err != nil {
		return nil, err
	}
	for tp, err := range s.Read(context.Background(), rev, f) {
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
			if _, err := s.Write(ctx, []rebac.Tuple{old}, nil); err != nil {
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
			_, err := s.Write(ctx,
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
	if _, err := e.Write(ctx, []rebac.Tuple{rebac.MustParseTuple("doc:a#viewer@user:alice")}, nil); err != nil {
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
		if _, err := s.Write(context.Background(), nil, []rebac.Tuple{bad}); err != nil {
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
	if _, err := s.Write(context.Background(), []rebac.Tuple{good, bad}, nil); !errors.Is(err, rebac.ErrInvalidTuple) {
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
	for _, name := range []string{"tuples", "_t1", "authz.tuples", "A_B.c9", strings.Repeat("t", 51), strings.Repeat("s", 63) + ".t"} {
		if _, err := rebac.NewSQLStore(db, rebac.PostgreSQL, rebac.WithSQLTable(name)); err != nil {
			t.Errorf("table %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{
		"", ".", "a.", ".a", "a.b.c", "1abc", "a-b", "a b", `a"b`, "a`b", "a;DROP TABLE x",
		"tuples\x00", "té", strings.Repeat("t", 52), strings.Repeat("s", 64) + ".t",
	} {
		if _, err := rebac.NewSQLStore(db, rebac.PostgreSQL, rebac.WithSQLTable(name)); err == nil {
			t.Errorf("table %q accepted", name)
		}
	}
}
