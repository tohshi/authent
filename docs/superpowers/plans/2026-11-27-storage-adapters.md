# Storage Adapters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep storage implementations optional at the package and module level while preserving each storage contract's behavior.

**Architecture:** Move the SQL session and ReBAC adapters into child packages of the root module, as `jwt/sqlreplay` already is. Keep memory stores in the core packages and Redis adapters in their independent module. Use a real core requirement in that module so a separate consumer can resolve it.

**Tech Stack:** Go 1.27.4; `database/sql`; `github.com/redis/go-redis/v9` in the Redis module only.

**Spec:** `docs/superpowers/specs/2026-11-27-storage-adapters-design.md`

## Global Constraints

- The root module must not gain a Redis client or SQL driver dependency.
- Store interfaces and runtime semantics stay the same; SQL constructors move with no forwarding aliases.
- Existing memory stores and the Redis module remain available.
- Do not modify the unrelated untracked `.claude/` directory.

## Review Focus

- A concurrent session save with a stale version still returns `session.ErrConflict`: covered by the moved session store tests and `sessiontest`.
- Session revocation by subject stays atomic with concurrent rotation: covered by `sessiontest` and the PostgreSQL integration test.
- An invalid tuple supplied to the SQL adapter still fails before writing: covered by the moved ReBAC tests.
- A filtered ReBAC SQL read still rejects malformed rows and exact-match false positives: covered by the moved ReBAC tests.
- A fresh consumer of the Redis module can resolve its core requirement without a local core `replace`: covered by the consumer build check.

---

### Task 1: Session SQL adapter package

**Files:** Move `session/sqlstore.go` to `session/sqlstore/sqlstore.go`; move `session/sqlstore_test.go` to `session/sqlstore/sqlstore_test.go`; modify `integration/session/sqlstore_test.go`.

**Interfaces:** Produce `sqlstore.New(db *sql.DB, dialect sqlstore.Dialect, opts ...sqlstore.Option) (*sqlstore.Store, error)`, `sqlstore.WithTable(name string) sqlstore.Option`, `sqlstore.DefaultTable`, and `sqlstore.PostgreSQL` / `MySQL` / `SQLite`. `*sqlstore.Store` implements `session.Store`.

- [ ] Update the existing unit and integration test imports and names to the new package; run `go test ./session/sqlstore` in the root and `go test ./session` in `integration/` to observe the expected compilation failure before moving code.
- [ ] Move and rename the SQL implementation's exported names. Keep all SQL statements, collision checks, and errors' `session:` prefix behavior intact. Add a compile-time `session.Store` assertion.
- [ ] Run `go test ./session/...` and the session SQL integration test when PostgreSQL is available; expect pass.
- [ ] Commit this task with `git add session/sqlstore.go session/sqlstore_test.go session/sqlstore integration/session/sqlstore_test.go && git commit -m 'session: isolate SQL store adapter'`.

### Task 2: ReBAC SQL adapter package

**Files:** Modify `rebac/tuple.go` and `rebac/caveat.go`; move `rebac/sqlstore.go` to `rebac/sqlstore/sqlstore.go`; move `rebac/sqlstore_test.go` to `rebac/sqlstore/sqlstore_test.go`; modify `integration/rebac/sqlstore_test.go`.

**Interfaces:** Produce `rebac.Tuple.Validate() error` for syntactic validation, and `sqlstore.New(db *sql.DB, dialect sqlstore.Dialect, opts ...sqlstore.Option) (*sqlstore.Store, error)`, `sqlstore.WithTable(name string) sqlstore.Option`, `sqlstore.DefaultTable`, and `sqlstore.PostgreSQL` / `MySQL` / `SQLite`. `*sqlstore.Store` implements `rebac.TupleStore`.

- [ ] Add a test that direct valid and invalid `rebac.Tuple` values return the expected result from `Validate`; run `go test ./rebac -run TestTupleValidate` and expect compilation failure.
- [ ] Export `Tuple.Validate` as a wrapper for the current private validator; run the focused test and expect pass.
- [ ] Update existing SQL tests and integration tests to the new package and run them to observe compilation failure before moving the implementation.
- [ ] Move SQL code, replace the shared unexported tuple identity, filter, and change-order helpers with local equivalents, and use `Tuple.Validate` to retain the existing validation rules. Add a compile-time `rebac.TupleStore` assertion.
- [ ] Run `go test ./rebac/...` and the ReBAC SQL integration test when PostgreSQL is available; expect pass.
- [ ] Commit this task with `git add rebac/tuple.go rebac/sqlstore.go rebac/sqlstore_test.go rebac/sqlstore integration/rebac/sqlstore_test.go && git commit -m 'rebac: isolate SQL tuple store adapter'`.

### Task 3: Optional module release and documentation

**Files:** Modify `redis/go.mod`, `redis/go.sum` if needed, `README.md`, `FEATURES.md`, `CONTRIBUTING.md`, and `.github/workflows/ci.yml`; add `.github/scripts/check-redis-consumer.sh`.

**Interfaces:** Preserve `redissession.New` and `redisreplay.New`. The Redis module requires a resolvable version of `github.com/tohshi/authent`; local development may use a workspace or local replace, but downstream consumers need neither.

- [ ] Construct and verify a resolvable root-module version for the Redis module; replace the all-zero placeholder requirement. In a temporary consumer module, point only the unreleased Redis module at the local checkout, import both Redis packages, and confirm `go test ./...` resolves the core without a core `replace`.
- [ ] Explain the three layers (core interfaces and memory, SQL subpackages, optional Redis module) and update SQL examples in README and FEATURES. Document the nested module's release/version rule in CONTRIBUTING.
- [ ] Update CI to run the consumer check as well as existing root, Redis, and integration module checks.
- [ ] Run `go test ./...`, `go test ./...` from `redis/`, `go vet ./...` in both modules, and the available integration tests. Confirm `go list -m all` in the root contains no Redis client or SQL driver.
- [ ] Commit this task with `git add redis/go.mod redis/go.sum README.md FEATURES.md CONTRIBUTING.md .github/workflows/ci.yml docs/superpowers && git commit -m 'authent: document and verify optional storage adapters'`.
