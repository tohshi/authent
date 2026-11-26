package rebac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"math"
	"slices"
	"strconv"
	"strings"
)

// SQLDialect selects the SQL syntax an SQLStore generates.
type SQLDialect int

const (
	// PostgreSQL uses $1-style placeholders and TEXT COLLATE "C" columns.
	PostgreSQL SQLDialect = iota + 1
	// MySQL uses ?-style placeholders and VARBINARY columns, so that
	// comparisons are byte-wise regardless of the server's collation.
	MySQL
	// SQLite uses ?-style placeholders and TEXT columns with the default
	// BINARY collation. It requires SQLite 3.24 or later.
	SQLite
)

func (d SQLDialect) String() string {
	switch d {
	case PostgreSQL:
		return "PostgreSQL"
	case MySQL:
		return "MySQL"
	case SQLite:
		return "SQLite"
	}
	return "SQLDialect(" + strconv.Itoa(int(d)) + ")"
}

func (d SQLDialect) placeholder(n int) string {
	if d == PostgreSQL {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

func (d SQLDialect) quote(ident string) string {
	if d == MySQL {
		return "`" + ident + "`"
	}
	return `"` + ident + `"`
}

// DefaultSQLTable is the table name an SQLStore uses unless WithSQLTable is
// given.
const DefaultSQLTable = "rebac_tuples"

// sqlColumns are the tuple columns of the table, in the order used by
// every statement. The primary key starts with them, so lookups by object
// and relation (the Engine's only access pattern) are index prefix scans.
var sqlColumns = [...]string{"object_type", "object_id", "relation", "subject_type", "subject_id", "subject_relation"}

// sqlLive is the deleted_rev of a tuple that has not been deleted.
const sqlLive = math.MaxInt64

// A table name leaves room for the longest name derived from it, an index
// name, within PostgreSQL's 63-byte limit.
const (
	sqlRevisionSuffix = "_revision"
	sqlMaxTableName   = 63 - len("_subject_idx")
)

func tupleArgs(t Tuple) []any {
	return []any{t.Object.Type, t.Object.ID, t.Relation, t.Subject.Object.Type, t.Subject.Object.ID, t.Subject.Relation}
}

// SQLStore is a TupleStore backed by a SQL database through database/sql.
// It does not import a driver: open db with the driver of your choice, such
// as github.com/jackc/pgx/v5/stdlib, github.com/go-sql-driver/mysql or
// modernc.org/sqlite, and pass the matching SQLDialect.
//
// Each version of a tuple is one row, with the revisions it was created
// and deleted at; an empty subject relation is stored as the empty string.
// A second table, named after the first with the suffix "_revision", holds
// the latest revision and the pruning horizon. Call CreateTable to create
// both, or apply CreateTableStatements with your migration tool. Deleted
// rows are kept for snapshot reads and Changes until Prune removes them.
//
// A Write locks the revision row for its transaction, so writes are
// serialized and their revisions follow commit order.
//
// Read loads all matching tuples and releases the connection before
// yielding any of them, so recursive reads by the Engine need only one
// connection at a time. As a defense against case-insensitive or otherwise
// non-binary collations on tables not created by CreateTable, rows that do
// not exactly match the filter are discarded, and rows that are not valid
// tuples make Read fail.
type SQLStore struct {
	db            *sql.DB
	dialect       SQLDialect
	table         string // quoted and qualified
	revTable      string
	createSQL     []string
	bumpSQL       string
	headSQL       string
	insertSQL     string
	deleteSQL     string
	replaceSQL    string // deletes the live version of a tuple if its caveat differs
	readPrefixSQL string // up to the join condition
	changeSQL     string
	horizSQL      string
	pruneSQL      string
}

// SQLStoreOption configures an SQLStore.
type SQLStoreOption func(*sqlStoreConfig)

type sqlStoreConfig struct {
	table string
}

// WithSQLTable sets the table name. It may be qualified by a schema, as in
// "authz.tuples". Each part must start with a letter or underscore and
// contain only ASCII letters, digits and underscores. The schema may be up
// to 63 bytes long and the table up to 51, which leaves room for the names
// derived from it. The default is DefaultSQLTable.
func WithSQLTable(name string) SQLStoreOption {
	return func(c *sqlStoreConfig) { c.table = name }
}

// NewSQLStore returns an SQLStore that stores tuples in db using dialect.
// It does not touch the database; see CreateTable.
func NewSQLStore(db *sql.DB, dialect SQLDialect, opts ...SQLStoreOption) (*SQLStore, error) {
	cfg := sqlStoreConfig{table: DefaultSQLTable}
	for _, opt := range opts {
		opt(&cfg)
	}
	switch {
	case db == nil:
		return nil, errors.New("rebac: nil *sql.DB")
	case dialect != PostgreSQL && dialect != MySQL && dialect != SQLite:
		return nil, fmt.Errorf("rebac: unknown SQL dialect %v", dialect)
	}
	schema, table, err := splitTableName(cfg.table)
	if err != nil {
		return nil, err
	}
	s := &SQLStore{db: db, dialect: dialect}
	s.buildStatements(schema, table)
	return s, nil
}

func splitTableName(name string) (schema, table string, err error) {
	parts := strings.Split(name, ".")
	if len(parts) > 2 {
		return "", "", fmt.Errorf("rebac: invalid SQL table name %q", name)
	}
	for _, p := range parts {
		if !validSQLIdent(p) {
			return "", "", fmt.Errorf("rebac: invalid SQL table name %q", name)
		}
	}
	if len(parts) == 2 {
		schema = parts[0]
	}
	table = parts[len(parts)-1]
	if len(table) > sqlMaxTableName {
		return "", "", fmt.Errorf("rebac: SQL table name %q is longer than %d bytes", name, sqlMaxTableName)
	}
	return schema, table, nil
}

// validSQLIdent reports whether s is safe to splice into a statement as a
// quoted identifier.
func validSQLIdent(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_'
		if !letter && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (s *SQLStore) buildStatements(schema, table string) {
	d := s.dialect
	qualify := func(name string) string {
		if schema != "" {
			return d.quote(schema) + "." + d.quote(name)
		}
		return d.quote(name)
	}
	s.table = qualify(table)
	s.revTable = qualify(table + sqlRevisionSuffix)

	cols := strings.Join(sqlColumns[:], ", ")
	subjectCols := "subject_type, subject_id, subject_relation"
	var defs []string
	for _, c := range sqlColumns {
		var typ string
		switch {
		case d == PostgreSQL:
			typ = `TEXT COLLATE "C"`
		case d == SQLite:
			typ = "TEXT"
		case c == "object_id" || c == "subject_id":
			typ = "VARBINARY(" + strconv.Itoa(maxIDLength) + ")"
		default:
			typ = "VARBINARY(64)"
		}
		defs = append(defs, c+" "+typ+" NOT NULL")
	}
	caveatName, caveatContext := `TEXT COLLATE "C"`, "TEXT"
	switch d {
	case SQLite:
		caveatName = "TEXT"
	case MySQL:
		caveatName, caveatContext = "VARBINARY(64)", "VARBINARY("+strconv.Itoa(maxContextLength)+")"
	}
	defs = append(defs, "caveat_name "+caveatName+" NOT NULL", "caveat_context "+caveatContext+" NOT NULL")
	defs = append(defs, "created_rev BIGINT NOT NULL", "deleted_rev BIGINT NOT NULL", "PRIMARY KEY ("+cols+", deleted_rev)")
	revDefs := "id INTEGER PRIMARY KEY, rev BIGINT NOT NULL, pruned_rev BIGINT NOT NULL"
	seed := "INSERT INTO " + s.revTable + " (id, rev, pruned_rev) VALUES (1, 0, 0)"
	ignore := " ON CONFLICT DO NOTHING"
	if d == MySQL {
		// Unlike INSERT IGNORE, this only ignores duplicate keys; other
		// errors, such as truncation, still fail the statement.
		ignore = " ON DUPLICATE KEY UPDATE id = id"
	}

	indexes := [][2]string{{"_subject_idx", subjectCols}, {"_created_idx", "created_rev"}, {"_deleted_idx", "deleted_rev"}}
	switch d {
	case PostgreSQL, SQLite:
		tableSuffix := ""
		if d == SQLite {
			tableSuffix = " WITHOUT ROWID"
		}
		s.createSQL = []string{"CREATE TABLE IF NOT EXISTS " + s.table + " (" + strings.Join(defs, ", ") + ")" + tableSuffix}
		for _, ix := range indexes {
			// PostgreSQL creates the index in the table's schema; SQLite
			// qualifies the index name, not the table, with the schema.
			name, on := d.quote(table+ix[0]), s.table
			if d == SQLite {
				name, on = qualify(table+ix[0]), d.quote(table)
			}
			s.createSQL = append(s.createSQL, "CREATE INDEX IF NOT EXISTS "+name+" ON "+on+" ("+ix[1]+")")
		}
	case MySQL:
		// MySQL has no CREATE INDEX IF NOT EXISTS; index names are per table.
		for _, ix := range indexes {
			defs = append(defs, "INDEX "+strings.TrimPrefix(ix[0], "_")+" ("+ix[1]+")")
		}
		s.createSQL = []string{"CREATE TABLE IF NOT EXISTS " + s.table + " (" + strings.Join(defs, ", ") + ")"}
	}
	s.createSQL = append(s.createSQL,
		"CREATE TABLE IF NOT EXISTS "+s.revTable+" ("+revDefs+")",
		seed+ignore)

	var params, conds []string
	for i, c := range sqlColumns {
		params = append(params, d.placeholder(i+1))
		conds = append(conds, c+" = "+d.placeholder(i+2))
	}
	n := len(sqlColumns)
	s.bumpSQL = "UPDATE " + s.revTable + " SET rev = rev + 1 WHERE id = 1"
	s.headSQL = "SELECT rev FROM " + s.revTable + " WHERE id = 1"
	s.insertSQL = "INSERT INTO " + s.table + " (" + cols + ", caveat_name, caveat_context, created_rev, deleted_rev) VALUES (" +
		strings.Join(params, ", ") + ", " + d.placeholder(n+1) + ", " + d.placeholder(n+2) + ", " +
		d.placeholder(n+3) + ", " + d.placeholder(n+4) + ")"
	if d == MySQL {
		s.insertSQL += " ON DUPLICATE KEY UPDATE object_type = object_type"
	} else {
		s.insertSQL += " ON CONFLICT DO NOTHING"
	}
	s.deleteSQL = "UPDATE " + s.table + " SET deleted_rev = " + d.placeholder(1) + " WHERE " +
		strings.Join(conds, " AND ") + " AND deleted_rev = " + d.placeholder(n+2)
	s.replaceSQL = s.deleteSQL + " AND (caveat_name <> " + d.placeholder(n+3) + " OR caveat_context <> " + d.placeholder(n+4) + ")"

	var tcols []string
	for _, c := range sqlColumns {
		tcols = append(tcols, "t."+c)
	}
	tcols = append(tcols, "t.caveat_name", "t.caveat_context")
	from := " FROM " + s.revTable + " r LEFT JOIN " + s.table + " t ON "
	s.readPrefixSQL = "SELECT r.rev, r.pruned_rev, " + strings.Join(tcols, ", ") + from
	s.changeSQL = "SELECT r.rev, r.pruned_rev, " + strings.Join(tcols, ", ") + ", t.created_rev, t.deleted_rev" + from +
		"(t.created_rev > " + d.placeholder(1) + " OR (t.deleted_rev > " + d.placeholder(2) +
		" AND t.deleted_rev < " + d.placeholder(3) + ")) WHERE r.id = 1"
	s.horizSQL = "UPDATE " + s.revTable + " SET pruned_rev = " + d.placeholder(1) + " WHERE id = 1 AND pruned_rev < " + d.placeholder(2)
	s.pruneSQL = "DELETE FROM " + s.table + " WHERE deleted_rev <= " + d.placeholder(1)
}

// CreateTableStatements returns the statements CreateTable runs, for use
// with a migration tool. The tuple table's primary key starts with the
// tuple columns; secondary indexes serve reverse (subject) lookups and
// Changes.
func (s *SQLStore) CreateTableStatements() []string {
	return slices.Clone(s.createSQL)
}

// CreateTable creates the tables and indexes if they do not exist.
func (s *SQLStore) CreateTable(ctx context.Context) error {
	for _, q := range s.createSQL {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("rebac: creating table %s: %w", s.table, err)
		}
	}
	return nil
}

// Write atomically deletes and then adds tuples in one transaction.
// Tuples to add must be valid; tuples to delete need not be, so that
// invalid rows written by other means can be removed.
func (s *SQLStore) Write(ctx context.Context, writes, deletes []Tuple) (Revision, error) {
	for _, t := range writes {
		if err := t.validate(); err != nil {
			return 0, err
		}
	}
	if len(writes) == 0 && len(deletes) == 0 {
		return s.Revision(ctx)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("rebac: beginning transaction: %w", err)
	}
	defer tx.Rollback() // no-op after a successful Commit

	if _, err := tx.ExecContext(ctx, s.bumpSQL); err != nil {
		return 0, fmt.Errorf("rebac: advancing revision: %w", err)
	}
	var rev int64
	if err := tx.QueryRowContext(ctx, s.headSQL).Scan(&rev); err != nil {
		return 0, fmt.Errorf("rebac: reading revision: %w", err)
	}
	var adds, dels []Tuple
	for _, nc := range netChanges(writes, deletes) {
		if nc.present {
			adds = append(adds, nc.t)
		} else {
			dels = append(dels, nc.t)
		}
	}
	if err := execEach(ctx, tx, s.deleteSQL, dels, func(t Tuple) []any {
		return append(append([]any{rev}, tupleArgs(t)...), int64(sqlLive))
	}); err != nil {
		return 0, fmt.Errorf("rebac: deleting tuple: %w", err)
	}
	if err := execEach(ctx, tx, s.replaceSQL, adds, func(t Tuple) []any {
		return append(append([]any{rev}, tupleArgs(t)...), int64(sqlLive), t.Caveat.Name, t.Caveat.Context)
	}); err != nil {
		return 0, fmt.Errorf("rebac: replacing tuple: %w", err)
	}
	if err := execEach(ctx, tx, s.insertSQL, adds, func(t Tuple) []any {
		return append(tupleArgs(t), t.Caveat.Name, t.Caveat.Context, rev, int64(sqlLive))
	}); err != nil {
		return 0, fmt.Errorf("rebac: writing tuple: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("rebac: committing tuples: %w", err)
	}
	return Revision(rev), nil
}

func execEach(ctx context.Context, tx *sql.Tx, query string, tuples []Tuple, args func(Tuple) []any) error {
	if len(tuples) == 0 {
		return nil
	}
	slices.SortFunc(tuples, func(a, b Tuple) int { return strings.Compare(a.String(), b.String()) })
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, t := range tuples {
		if _, err := stmt.ExecContext(ctx, args(t)...); err != nil {
			return fmt.Errorf("%s: %w", t, err)
		}
	}
	return nil
}

// Revision returns the latest revision.
func (s *SQLStore) Revision(ctx context.Context) (Revision, error) {
	var rev int64
	if err := s.db.QueryRowContext(ctx, s.headSQL).Scan(&rev); err != nil {
		return 0, fmt.Errorf("rebac: reading revision: %w", err)
	}
	return Revision(rev), nil
}

// Read yields the tuples matching f at revision rev. The query runs when
// iteration starts. It reads the latest revision and the pruning horizon in
// the same statement, so a concurrent Prune cannot go unnoticed.
func (s *SQLStore) Read(ctx context.Context, rev Revision, f Filter) iter.Seq2[Tuple, error] {
	return func(yield func(Tuple, error) bool) {
		tuples, err := s.read(ctx, rev, f)
		if err != nil {
			yield(Tuple{}, err)
			return
		}
		for _, t := range tuples {
			if !yield(t, nil) {
				return
			}
		}
	}
}

func (s *SQLStore) read(ctx context.Context, rev Revision, f Filter) ([]Tuple, error) {
	if rev >= sqlLive {
		return nil, fmt.Errorf("%w: %d", ErrFutureRevision, rev)
	}
	var conds []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, cond+s.dialect.placeholder(len(args)))
	}
	if f.ObjectType != "" {
		add("t.object_type = ", f.ObjectType)
	}
	if f.ObjectID != "" {
		add("t.object_id = ", f.ObjectID)
	}
	if f.Relation != "" {
		add("t.relation = ", f.Relation)
	}
	if f.Subject != nil {
		add("t.subject_type = ", f.Subject.Object.Type)
		add("t.subject_id = ", f.Subject.Object.ID)
		add("t.subject_relation = ", f.Subject.Relation)
	}
	add("t.created_rev <= ", int64(rev))
	add("t.deleted_rev > ", int64(rev))
	query := s.readPrefixSQL + strings.Join(conds, " AND ") + " WHERE r.id = 1"

	var out []Tuple
	err := s.query(ctx, rev, query, args, func(cols []sql.NullString, _ ...int64) error {
		t := Tuple{
			Object:   Obj(cols[0].String, cols[1].String),
			Relation: cols[2].String,
			Subject:  Subject{Object: Obj(cols[3].String, cols[4].String), Relation: cols[5].String},
			Caveat:   TupleCaveat{Name: cols[6].String, Context: cols[7].String},
		}
		if err := t.validate(); err != nil {
			return fmt.Errorf("rebac: invalid tuple in %s: %w", s.table, err)
		}
		if f.matches(t) {
			out = append(out, t)
		}
		return nil
	})
	return out, err
}

// query runs a statement whose rows start with the latest revision and the
// pruning horizon, checks that rev is available, and calls row for every
// row that has tuple columns, with the trailing int64 columns, if any.
func (s *SQLStore) query(ctx context.Context, rev Revision, query string, args []any, row func(cols []sql.NullString, extra ...int64) error) error {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("rebac: querying tuples: %w", err)
	}
	defer rows.Close()
	n, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("rebac: querying tuples: %w", err)
	}
	cols := make([]sql.NullString, len(sqlColumns)+2)
	extra := make([]sql.NullInt64, len(n)-2-len(cols))
	dest := []any{new(int64), new(int64)}
	for i := range cols {
		dest = append(dest, &cols[i])
	}
	for i := range extra {
		dest = append(dest, &extra[i])
	}
	first := true
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return fmt.Errorf("rebac: scanning tuple: %w", err)
		}
		if first {
			first = false
			head, horizon := Revision(*dest[0].(*int64)), Revision(*dest[1].(*int64))
			switch {
			case rev > head:
				return fmt.Errorf("%w: %d is after %d", ErrFutureRevision, rev, head)
			case rev < horizon:
				return fmt.Errorf("%w: %d is before %d", ErrRevisionExpired, rev, horizon)
			}
		}
		if !cols[0].Valid {
			continue
		}
		ints := make([]int64, len(extra))
		for i, e := range extra {
			ints[i] = e.Int64
		}
		if err := row(cols, ints...); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rebac: reading tuples: %w", err)
	}
	if first {
		return fmt.Errorf("rebac: %s has no revision row", s.revTable)
	}
	return nil
}

// Changes yields the changes made after revision after. It loads them all
// before yielding the first.
func (s *SQLStore) Changes(ctx context.Context, after Revision) iter.Seq2[Change, error] {
	return func(yield func(Change, error) bool) {
		changes, err := s.changes(ctx, after)
		if err != nil {
			yield(Change{}, err)
			return
		}
		for _, c := range changes {
			if !yield(c, nil) {
				return
			}
		}
	}
}

func (s *SQLStore) changes(ctx context.Context, after Revision) ([]Change, error) {
	if after >= sqlLive {
		return nil, fmt.Errorf("%w: %d", ErrFutureRevision, after)
	}
	var out []Change
	args := []any{int64(after), int64(after), int64(sqlLive)}
	err := s.query(ctx, after, s.changeSQL, args, func(cols []sql.NullString, revs ...int64) error {
		t := Tuple{
			Object:   Obj(cols[0].String, cols[1].String),
			Relation: cols[2].String,
			Subject:  Subject{Object: Obj(cols[3].String, cols[4].String), Relation: cols[5].String},
			Caveat:   TupleCaveat{Name: cols[6].String, Context: cols[7].String},
		}
		if err := t.validate(); err != nil {
			return fmt.Errorf("rebac: invalid tuple in %s: %w", s.table, err)
		}
		if created := Revision(revs[0]); created > after {
			out = append(out, Change{created, ChangeWrite, t})
		}
		if deleted := revs[1]; deleted < sqlLive && Revision(deleted) > after {
			out = append(out, Change{Revision(deleted), ChangeDelete, t})
		}
		return nil
	})
	slices.SortFunc(out, compareChanges)
	return out, err
}

// Prune deletes the rows of tuples deleted at or before revision before.
// Afterwards, reading at an earlier revision or asking for changes after
// one fails with ErrRevisionExpired. Queries in progress at such a revision
// fail too, so leave a margin for them.
func (s *SQLStore) Prune(ctx context.Context, before Revision) error {
	if before >= sqlLive {
		return fmt.Errorf("%w: %d", ErrFutureRevision, before)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rebac: beginning transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.horizSQL, int64(before), int64(before)); err != nil {
		return fmt.Errorf("rebac: pruning: %w", err)
	}
	var head int64
	if err := tx.QueryRowContext(ctx, s.headSQL).Scan(&head); err != nil {
		return fmt.Errorf("rebac: reading revision: %w", err)
	}
	if int64(before) > head {
		return fmt.Errorf("%w: %d is after %d", ErrFutureRevision, before, head)
	}
	if _, err := tx.ExecContext(ctx, s.pruneSQL, int64(before)); err != nil {
		return fmt.Errorf("rebac: pruning: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("rebac: pruning: %w", err)
	}
	return nil
}
