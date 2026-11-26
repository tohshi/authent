package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
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
	// BINARY collation.
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
const DefaultSQLTable = "authent_sessions"

// maxSQLSubject is the longest subject, in bytes, an SQLStore accepts. It
// sizes the MySQL column.
const maxSQLSubject = 1024

// sqlColumns are the columns every SELECT returns, in this order.
const sqlColumns = "token_hash, subject, version, expires_at, data"

// SQLStore is a Store backed by a SQL database through database/sql. It
// does not import a driver: open db with the driver of your choice, such
// as github.com/jackc/pgx/v5/stdlib, github.com/go-sql-driver/mysql or
// modernc.org/sqlite, and pass the matching SQLDialect.
//
// Each session is one row keyed by the token hash, with the subject, the
// version, the expiry in Unix nanoseconds and the encoded session. Every
// operation is a single statement; versions are compared in the WHERE
// clause. Call CreateTable to create the table, or apply
// CreateTableStatements with your migration tool, and call DeleteExpired
// periodically to remove expired rows.
//
// As a defense against case-insensitive or otherwise non-binary
// collations on tables not created by CreateTable, rows whose token hash
// or subject does not exactly match the lookup are ignored.
type SQLStore struct {
	db      *sql.DB
	dialect SQLDialect
	table   string
	now     func() time.Time

	createSQL        []string
	insertSQL        string
	updateSQL        string
	selectKeySQL     string
	selectLiveSQL    string
	selectSubjectSQL string
	deleteSQL        string
	deleteVersionSQL string
	deleteSubjectSQL string
	deleteExpiredSQL string
}

// SQLStoreOption configures an SQLStore.
type SQLStoreOption func(*sqlStoreConfig)

type sqlStoreConfig struct {
	table string
}

// WithSQLTable sets the table name. It may be qualified by a schema, as in
// "auth.sessions". Each part must start with a letter or underscore and
// contain only ASCII letters, digits and underscores. The schema may be up
// to 63 bytes long and the table up to 51, so that the index names derived
// from it fit PostgreSQL's limit. The default is DefaultSQLTable.
func WithSQLTable(name string) SQLStoreOption {
	return func(c *sqlStoreConfig) { c.table = name }
}

// NewSQLStore returns an SQLStore that stores sessions in db using
// dialect. It does not touch the database; see CreateTable.
func NewSQLStore(db *sql.DB, dialect SQLDialect, opts ...SQLStoreOption) (*SQLStore, error) {
	cfg := sqlStoreConfig{table: DefaultSQLTable}
	for _, opt := range opts {
		opt(&cfg)
	}
	switch {
	case db == nil:
		return nil, errors.New("session: nil *sql.DB")
	case dialect != PostgreSQL && dialect != MySQL && dialect != SQLite:
		return nil, fmt.Errorf("session: unknown SQL dialect %v", dialect)
	}
	schema, table, err := splitTableName(cfg.table)
	if err != nil {
		return nil, err
	}
	s := &SQLStore{db: db, dialect: dialect, now: time.Now}
	s.buildStatements(schema, table)
	return s, nil
}

func splitTableName(name string) (schema, table string, err error) {
	parts := strings.Split(name, ".")
	if len(parts) > 2 || !validSQLIdent(parts[len(parts)-1], 51) || len(parts) == 2 && !validSQLIdent(parts[0], 63) {
		return "", "", fmt.Errorf("session: invalid SQL table name %q", name)
	}
	if len(parts) == 2 {
		return parts[0], parts[1], nil
	}
	return "", parts[0], nil
}

// validSQLIdent reports whether s is safe to splice into a statement as a
// quoted identifier.
func validSQLIdent(s string, maxLen int) bool {
	if len(s) == 0 || len(s) > maxLen {
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
	p := d.placeholder

	var cols string
	switch d {
	case PostgreSQL:
		cols = `token_hash TEXT COLLATE "C" PRIMARY KEY, subject TEXT COLLATE "C" NOT NULL, ` +
			"version BIGINT NOT NULL, expires_at BIGINT NOT NULL, data BYTEA NOT NULL"
	case MySQL:
		cols = "token_hash VARBINARY(64) PRIMARY KEY, subject VARBINARY(" + strconv.Itoa(maxSQLSubject) + ") NOT NULL, " +
			"version BIGINT NOT NULL, expires_at BIGINT NOT NULL, data LONGBLOB NOT NULL"
	case SQLite:
		cols = "token_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, " +
			"version INTEGER NOT NULL, expires_at INTEGER NOT NULL, data BLOB NOT NULL"
	}
	createIndex := func(suffix, col string) string {
		// PostgreSQL creates the index in the table's schema; SQLite
		// qualifies the index name, not the table, with the schema.
		index, on := d.quote(table+suffix), qualified
		if d == SQLite {
			on = d.quote(table)
			if schema != "" {
				index = d.quote(schema) + "." + index
			}
		}
		return "CREATE INDEX IF NOT EXISTS " + index + " ON " + on + " (" + col + ")"
	}
	if d == MySQL {
		// MySQL has no CREATE INDEX IF NOT EXISTS; index names are per table.
		s.createSQL = []string{"CREATE TABLE IF NOT EXISTS " + qualified + " (" + cols +
			", INDEX subject_idx (subject), INDEX expires_idx (expires_at))"}
	} else {
		s.createSQL = []string{
			"CREATE TABLE IF NOT EXISTS " + qualified + " (" + cols + ")",
			createIndex("_subject_idx", "subject"),
			createIndex("_expires_idx", "expires_at"),
		}
	}

	s.insertSQL = "INSERT INTO " + qualified + " (" + sqlColumns + ") VALUES (" +
		strings.Join([]string{p(1), p(2), p(3), p(4), p(5)}, ", ") + ")"
	s.updateSQL = "UPDATE " + qualified + " SET version = " + p(1) + ", expires_at = " + p(2) + ", data = " + p(3) +
		" WHERE token_hash = " + p(4) + " AND version = " + p(5) + " AND expires_at > " + p(6)
	selectSQL := "SELECT " + sqlColumns + " FROM " + qualified + " WHERE "
	s.selectKeySQL = selectSQL + "token_hash = " + p(1)
	s.selectLiveSQL = selectSQL + "token_hash = " + p(1) + " AND expires_at > " + p(2)
	s.selectSubjectSQL = selectSQL + "subject = " + p(1) + " AND expires_at > " + p(2)
	deleteSQL := "DELETE FROM " + qualified + " WHERE "
	s.deleteSQL = deleteSQL + "token_hash = " + p(1)
	s.deleteVersionSQL = deleteSQL + "token_hash = " + p(1) + " AND version = " + p(2) + " AND expires_at > " + p(3)
	s.deleteSubjectSQL = deleteSQL + "subject = " + p(1)
	s.deleteExpiredSQL = deleteSQL + "expires_at <= " + p(1)
}

// CreateTableStatements returns the statements CreateTable runs, for use
// with a migration tool. Besides the table, they create indexes on the
// subject, for List and DeleteSubject, and on the expiry, for
// DeleteExpired.
func (s *SQLStore) CreateTableStatements() []string {
	return slices.Clone(s.createSQL)
}

// CreateTable creates the session table and its indexes if they do not
// exist.
func (s *SQLStore) CreateTable(ctx context.Context) error {
	for _, q := range s.createSQL {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("session: creating table %s: %w", s.table, err)
		}
	}
	return nil
}

func (s *SQLStore) Load(ctx context.Context, key string) (Record, error) {
	r, err := s.scanOne(s.db.QueryRowContext(ctx, s.selectLiveSQL, key, s.now().UnixNano()), key)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	return r, err
}

// scanOne scans the row for key, reporting a row for another key as
// sql.ErrNoRows.
func (s *SQLStore) scanOne(row *sql.Row, key string) (Record, error) {
	got, r, err := s.scan(row)
	if err == nil && got != key {
		err = sql.ErrNoRows
	}
	return r, err
}

func (s *SQLStore) scan(row interface{ Scan(...any) error }) (string, Record, error) {
	var (
		key              string
		r                Record
		version, expires int64
	)
	if err := row.Scan(&key, &r.Subject, &version, &expires, &r.Data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", Record{}, err
		}
		return "", Record{}, fmt.Errorf("session: reading session from %s: %w", s.table, err)
	}
	if version < 1 {
		return "", Record{}, fmt.Errorf("session: invalid version %d in %s", version, s.table)
	}
	r.Version = uint64(version)
	r.ExpiresAt = time.Unix(0, expires)
	return key, r, nil
}

func (s *SQLStore) Save(ctx context.Context, key string, r Record) error {
	switch {
	case len(r.Subject) > maxSQLSubject:
		return fmt.Errorf("session: subject longer than %d bytes", maxSQLSubject)
	case r.Version == 0:
		return ErrConflict
	case r.Version > math.MaxInt64:
		return fmt.Errorf("session: version %d out of range", r.Version)
	case r.Version == 1:
		return s.insert(ctx, key, r)
	}
	res, err := s.db.ExecContext(ctx, s.updateSQL,
		int64(r.Version), r.ExpiresAt.UnixNano(), r.Data, key, int64(r.Version-1), s.now().UnixNano())
	return s.changed(res, err, "saving")
}

func (s *SQLStore) insert(ctx context.Context, key string, r Record) error {
	_, err := s.db.ExecContext(ctx, s.insertSQL, key, r.Subject, int64(1), r.ExpiresAt.UnixNano(), r.Data)
	if err == nil {
		return nil
	}
	// Drivers report duplicate keys differently, so look for the row.
	if _, lookErr := s.scanOne(s.db.QueryRowContext(ctx, s.selectKeySQL, key), key); lookErr == nil {
		return ErrConflict
	}
	return fmt.Errorf("session: inserting session: %w", err)
}

// changed returns ErrConflict unless the statement affected a row.
func (s *SQLStore) changed(res sql.Result, err error, op string) error {
	if err != nil {
		return fmt.Errorf("session: %s session: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("session: %s session: %w", op, err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *SQLStore) Delete(ctx context.Context, key string, version uint64) error {
	if version == 0 {
		if _, err := s.db.ExecContext(ctx, s.deleteSQL, key); err != nil {
			return fmt.Errorf("session: deleting session: %w", err)
		}
		return nil
	}
	if version > math.MaxInt64 {
		return ErrConflict
	}
	res, err := s.db.ExecContext(ctx, s.deleteVersionSQL, key, int64(version), s.now().UnixNano())
	return s.changed(res, err, "deleting")
}

func (s *SQLStore) List(ctx context.Context, subject string) (map[string]Record, error) {
	rows, err := s.db.QueryContext(ctx, s.selectSubjectSQL, subject, s.now().UnixNano())
	if err != nil {
		return nil, fmt.Errorf("session: listing sessions: %w", err)
	}
	defer rows.Close()
	out := map[string]Record{}
	for rows.Next() {
		key, r, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		if r.Subject == subject {
			out[key] = r
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session: listing sessions: %w", err)
	}
	return out, nil
}

func (s *SQLStore) DeleteSubject(ctx context.Context, subject string) error {
	if _, err := s.db.ExecContext(ctx, s.deleteSubjectSQL, subject); err != nil {
		return fmt.Errorf("session: deleting sessions of subject: %w", err)
	}
	return nil
}

// DeleteExpired removes expired sessions. Load and List already ignore
// them; call DeleteExpired periodically so that they do not accumulate.
func (s *SQLStore) DeleteExpired(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, s.deleteExpiredSQL, s.now().UnixNano()); err != nil {
		return fmt.Errorf("session: deleting expired sessions: %w", err)
	}
	return nil
}
