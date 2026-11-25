package rebac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"
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

// sqlColumns are the columns of the tuple table, in the order used by every
// statement. The primary key covers all of them, in this order, so lookups
// by object and relation (the Engine's only access pattern) are index
// prefix scans.
var sqlColumns = [...]string{"object_type", "object_id", "relation", "subject_type", "subject_id", "subject_relation"}

func tupleArgs(t Tuple) []any {
	return []any{t.Object.Type, t.Object.ID, t.Relation, t.Subject.Object.Type, t.Subject.Object.ID, t.Subject.Relation}
}

// SQLStore is a TupleStore backed by a SQL database through database/sql.
// It does not import a driver: open db with the driver of your choice, such
// as github.com/jackc/pgx/v5/stdlib, github.com/go-sql-driver/mysql or
// modernc.org/sqlite, and pass the matching SQLDialect.
//
// Each tuple is one row in a single table; an empty subject relation is
// stored as the empty string. Call CreateTable to create the table, or
// apply CreateTableStatements with your migration tool.
//
// Read loads all matching tuples and releases the connection before
// yielding any of them, so recursive reads by the Engine need only one
// connection at a time. As a defense against case-insensitive or otherwise
// non-binary collations on tables not created by CreateTable, rows that do
// not exactly match the filter are discarded, and rows that are not valid
// tuples make Read fail.
type SQLStore struct {
	db        *sql.DB
	dialect   SQLDialect
	createSQL []string
	insertSQL string
	deleteSQL string
	selectSQL string
	table     string
}

// SQLStoreOption configures an SQLStore.
type SQLStoreOption func(*sqlStoreConfig)

type sqlStoreConfig struct {
	table string
}

// WithSQLTable sets the table name. It may be qualified by a schema, as in
// "authz.tuples". Each part must start with a letter or underscore, contain
// only ASCII letters, digits and underscores, and be at most 63 bytes long.
// The default is DefaultSQLTable.
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
		return parts[0], parts[1], nil
	}
	return "", parts[0], nil
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
	qualified := d.quote(table)
	if schema != "" {
		qualified = d.quote(schema) + "." + qualified
	}
	s.table = qualified

	cols := strings.Join(sqlColumns[:], ", ")
	subjectCols := "subject_type, subject_id, subject_relation"
	var params, conds []string
	for i, c := range sqlColumns {
		params = append(params, d.placeholder(i+1))
		conds = append(conds, c+" = "+d.placeholder(i+1))
	}

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
	defs = append(defs, "PRIMARY KEY ("+cols+")")

	indexName := table + "_subject_idx"
	switch d {
	case PostgreSQL:
		// The index is created in the table's schema.
		s.createSQL = []string{
			"CREATE TABLE IF NOT EXISTS " + qualified + " (" + strings.Join(defs, ", ") + ")",
			"CREATE INDEX IF NOT EXISTS " + d.quote(indexName) + " ON " + qualified + " (" + subjectCols + ")",
		}
	case MySQL:
		// MySQL has no CREATE INDEX IF NOT EXISTS; index names are per table.
		defs = append(defs, "INDEX subject_idx ("+subjectCols+")")
		s.createSQL = []string{
			"CREATE TABLE IF NOT EXISTS " + qualified + " (" + strings.Join(defs, ", ") + ")",
		}
	case SQLite:
		// SQLite qualifies the index name, not the table, with the schema.
		index := d.quote(indexName)
		if schema != "" {
			index = d.quote(schema) + "." + index
		}
		s.createSQL = []string{
			"CREATE TABLE IF NOT EXISTS " + qualified + " (" + strings.Join(defs, ", ") + ") WITHOUT ROWID",
			"CREATE INDEX IF NOT EXISTS " + index + " ON " + d.quote(table) + " (" + subjectCols + ")",
		}
	}

	s.insertSQL = "INSERT INTO " + qualified + " (" + cols + ") VALUES (" + strings.Join(params, ", ") + ")"
	if d == MySQL {
		// Unlike INSERT IGNORE, this only ignores duplicate keys; other
		// errors, such as truncation, still fail the write.
		s.insertSQL += " ON DUPLICATE KEY UPDATE object_type = object_type"
	} else {
		s.insertSQL += " ON CONFLICT DO NOTHING"
	}
	s.deleteSQL = "DELETE FROM " + qualified + " WHERE " + strings.Join(conds, " AND ")
	s.selectSQL = "SELECT " + cols + " FROM " + qualified
}

// CreateTableStatements returns the statements CreateTable runs, for use
// with a migration tool. The table's primary key covers all columns; a
// secondary index on the subject columns serves reverse (subject) lookups.
func (s *SQLStore) CreateTableStatements() []string {
	return slices.Clone(s.createSQL)
}

// CreateTable creates the tuple table and its indexes if they do not exist.
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
func (s *SQLStore) Write(ctx context.Context, writes, deletes []Tuple) error {
	for _, t := range writes {
		if err := t.validate(); err != nil {
			return err
		}
	}
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rebac: beginning transaction: %w", err)
	}
	defer tx.Rollback() // no-op after a successful Commit

	if err := execEach(ctx, tx, s.deleteSQL, deletes); err != nil {
		return fmt.Errorf("rebac: deleting tuple: %w", err)
	}
	if err := execEach(ctx, tx, s.insertSQL, writes); err != nil {
		return fmt.Errorf("rebac: writing tuple: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("rebac: committing tuples: %w", err)
	}
	return nil
}

func execEach(ctx context.Context, tx *sql.Tx, query string, tuples []Tuple) error {
	if len(tuples) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, t := range tuples {
		if _, err := stmt.ExecContext(ctx, tupleArgs(t)...); err != nil {
			return fmt.Errorf("%s: %w", t, err)
		}
	}
	return nil
}

// Read yields the tuples matching f. The query runs when iteration starts.
func (s *SQLStore) Read(ctx context.Context, f Filter) iter.Seq2[Tuple, error] {
	return func(yield func(Tuple, error) bool) {
		tuples, err := s.read(ctx, f)
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

func (s *SQLStore) read(ctx context.Context, f Filter) ([]Tuple, error) {
	var conds []string
	var args []any
	add := func(col, val string) {
		args = append(args, val)
		conds = append(conds, col+" = "+s.dialect.placeholder(len(args)))
	}
	if f.ObjectType != "" {
		add("object_type", f.ObjectType)
	}
	if f.ObjectID != "" {
		add("object_id", f.ObjectID)
	}
	if f.Relation != "" {
		add("relation", f.Relation)
	}
	if f.Subject != nil {
		add("subject_type", f.Subject.Object.Type)
		add("subject_id", f.Subject.Object.ID)
		add("subject_relation", f.Subject.Relation)
	}
	query := s.selectSQL
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("rebac: querying tuples: %w", err)
	}
	defer rows.Close()
	var out []Tuple
	for rows.Next() {
		var t Tuple
		if err := rows.Scan(&t.Object.Type, &t.Object.ID, &t.Relation,
			&t.Subject.Object.Type, &t.Subject.Object.ID, &t.Subject.Relation); err != nil {
			return nil, fmt.Errorf("rebac: scanning tuple: %w", err)
		}
		if err := t.validate(); err != nil {
			return nil, fmt.Errorf("rebac: invalid tuple in %s: %w", s.table, err)
		}
		if f.matches(t) {
			out = append(out, t)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rebac: reading tuples: %w", err)
	}
	return out, nil
}
