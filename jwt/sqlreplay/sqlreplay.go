// Package sqlreplay is a jwt.ReplayCache backed by a SQL database through
// database/sql, so that several servers detect replayed tokens and DPoP
// proofs together.
//
// It does not import a driver: open the database with the driver of your
// choice, such as github.com/jackc/pgx/v5/stdlib or modernc.org/sqlite,
// and pass the matching Dialect.
package sqlreplay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Dialect selects the SQL syntax a Cache generates.
//
// MySQL is not supported: whether its INSERT ... ON DUPLICATE KEY UPDATE
// changed a row cannot be told from the affected-row count when the
// connection sets CLIENT_FOUND_ROWS, and guessing wrong would accept a
// replay.
type Dialect int

const (
	// PostgreSQL uses $1-style placeholders and a TEXT COLLATE "C" key.
	PostgreSQL Dialect = iota + 1
	// SQLite uses ?-style placeholders. It requires SQLite 3.24 or later.
	SQLite
)

func (d Dialect) String() string {
	switch d {
	case PostgreSQL:
		return "PostgreSQL"
	case SQLite:
		return "SQLite"
	}
	return "Dialect(" + strconv.Itoa(int(d)) + ")"
}

func (d Dialect) placeholder(n int) string {
	if d == PostgreSQL {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

// DefaultTable is the table name a Cache uses unless WithTable is given.
const DefaultTable = "jwt_replay"

// Cache is a jwt.ReplayCache that keeps one row per recorded id with its
// expiry in Unix milliseconds. Expired rows are replaced on the next Add
// of the same id; call DeleteExpired periodically to remove the others.
// It is safe for concurrent use.
type Cache struct {
	db        *sql.DB
	now       func() time.Time
	createSQL []string
	addSQL    string
	deleteSQL string
}

// Option configures a Cache.
type Option func(*config)

type config struct {
	table string
	now   func() time.Time
}

// WithTable sets the table name. It may be qualified by a schema, as in
// "auth.jwt_replay". Each part must start with a letter or underscore,
// contain only ASCII letters, digits and underscores, and be at most 63
// bytes long. The default is DefaultTable.
func WithTable(name string) Option { return func(c *config) { c.table = name } }

// WithClock overrides the clock, for tests. Expiry is decided by the
// clock of the server calling Add, not by the database's clock.
func WithClock(now func() time.Time) Option { return func(c *config) { c.now = now } }

// New returns a Cache that stores ids in db using dialect. It does not
// touch the database; see CreateTable.
func New(db *sql.DB, dialect Dialect, opts ...Option) (*Cache, error) {
	cfg := config{table: DefaultTable, now: time.Now}
	for _, opt := range opts {
		opt(&cfg)
	}
	if db == nil {
		return nil, errors.New("sqlreplay: nil *sql.DB")
	}
	if dialect != PostgreSQL && dialect != SQLite {
		return nil, fmt.Errorf("sqlreplay: unsupported SQL dialect %v", dialect)
	}
	schema, table, ok := strings.Cut(cfg.table, ".")
	if !ok {
		schema, table = "", schema
	}
	if (ok && !validIdent(schema)) || !validIdent(table) {
		return nil, fmt.Errorf("sqlreplay: invalid SQL table name %q", cfg.table)
	}
	c := &Cache{db: db, now: cfg.now}
	c.buildStatements(dialect, schema, table)
	return c, nil
}

func validIdent(s string) bool {
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

func (c *Cache) buildStatements(d Dialect, schema, table string) {
	quote := func(s string) string { return `"` + s + `"` }
	qualified := quote(table)
	if schema != "" {
		qualified = quote(schema) + "." + qualified
	}
	index := quote(table + "_expires_idx")
	switch d {
	case PostgreSQL:
		c.createSQL = []string{
			"CREATE TABLE IF NOT EXISTS " + qualified + ` (id TEXT COLLATE "C" NOT NULL PRIMARY KEY, expires_at BIGINT NOT NULL)`,
			"CREATE INDEX IF NOT EXISTS " + index + " ON " + qualified + " (expires_at)",
		}
	case SQLite:
		// SQLite qualifies the index name, not the table, with the schema.
		if schema != "" {
			index = quote(schema) + "." + index
		}
		c.createSQL = []string{
			"CREATE TABLE IF NOT EXISTS " + qualified + " (id TEXT NOT NULL PRIMARY KEY, expires_at INTEGER NOT NULL) WITHOUT ROWID",
			"CREATE INDEX IF NOT EXISTS " + index + " ON " + quote(table) + " (expires_at)",
		}
	}
	p := d.placeholder
	c.addSQL = "INSERT INTO " + qualified + " (id, expires_at) VALUES (" + p(1) + ", " + p(2) + ")" +
		" ON CONFLICT (id) DO UPDATE SET expires_at = excluded.expires_at" +
		" WHERE " + quote(table) + ".expires_at <= " + p(3)
	c.deleteSQL = "DELETE FROM " + qualified + " WHERE expires_at <= " + p(1)
}

// CreateTableStatements returns the statements CreateTable runs, for use
// with a migration tool.
func (c *Cache) CreateTableStatements() []string { return slices.Clone(c.createSQL) }

// CreateTable creates the table and its expiry index if they do not
// exist.
func (c *Cache) CreateTable(ctx context.Context) error {
	for _, stmt := range c.createSQL {
		if _, err := c.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlreplay: create table: %w", err)
		}
	}
	return nil
}

// Add implements jwt.ReplayCache. A ttl below one second is raised to one
// second, as in jwt.MemoryReplayCache.
func (c *Cache) Add(ctx context.Context, id string, ttl time.Duration) (bool, error) {
	now := c.now()
	res, err := c.db.ExecContext(ctx, c.addSQL, id, now.Add(max(ttl, time.Second)).UnixMilli(), now.UnixMilli())
	if err != nil {
		return false, fmt.Errorf("sqlreplay: add: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("sqlreplay: add: %w", err)
	}
	switch n {
	case 0:
		return false, nil
	case 1:
		return true, nil
	}
	return false, fmt.Errorf("sqlreplay: add affected %d rows", n)
}

// DeleteExpired removes expired rows and returns how many it removed.
func (c *Cache) DeleteExpired(ctx context.Context) (int64, error) {
	res, err := c.db.ExecContext(ctx, c.deleteSQL, c.now().UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("sqlreplay: delete expired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlreplay: delete expired: %w", err)
	}
	return n, nil
}
