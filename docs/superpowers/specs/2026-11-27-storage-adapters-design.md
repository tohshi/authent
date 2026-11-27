# Storage adapter layout

Status: approved; API compatibility is not a constraint

## Intent

Keep `authent` small for applications that use only its core packages. Let an
application choose an in-memory, SQL, Redis, or custom store through the
existing domain-specific interfaces without making unrelated storage clients
dependencies of the core module.

## Approaches

1. Keep SQL stores in their core packages and repair the Redis module's
   release setup. This changes least, but makes the core packages own the
   storage-specific constructors and dialects.
2. Move SQL stores into `session/sqlstore` and `rebac/sqlstore` within the
   root Go module; retain Redis in its separate module. This keeps external
   dependencies small and presents each SQL implementation as an optional
   adapter. **Chosen.**
3. Remove the supplied stores. This reduces maintained code but makes every
   application implement atomic session updates, replay checks, and ReBAC
   revisions before it can use those features.

## Design

- Keep `session.Store`, `rebac.TupleStore`, `jwt.ReplayCache`, and the other
  domain-specific storage contracts. Do not introduce a universal key-value
  interface: these contracts require different atomic operations.
- Keep in-memory stores in the core for tests and simple deployments. Move
  `session.SQLStore` and `rebac.SQLStore` to the subpackages above, with
  `New`, `Store`, `Dialect`, dialect constants, and `WithTable` following the
  existing `jwt/sqlreplay` style. These stay in the root Go module because
  `database/sql` imports no driver or third-party database library.
- Export syntactic `rebac.Tuple.Validate` for the SQL adapter and custom
  stores. Keep the small tuple identity, filter, and change-order operations
  local to the SQL adapter rather than exposing more internals. Check that
  these retain the current store semantics through the conformance suite.
- Export `rebac.MaxIDLength` and `rebac.MaxCaveatContextLength` so SQL column
  sizing uses the same limits as tuple validation.
- Keep Redis adapters in the separate `github.com/tohshi/authent/redis`
  module, which alone requires `go-redis`.
- Replace the Redis module's placeholder core requirement with a resolvable
  core version. Keep local development possible, and verify a fresh consumer
  module can build the Redis adapters without adding its own `replace`.
- Explain the module boundary and store selection in the README and document
  how the nested Redis module is released. Update examples and integration
  tests to the new SQL imports. Do not keep forwarding aliases in `session`
  and `rebac`; they would leave backend-specific names in the core interface.

## Verification

Run tests for the root and Redis modules, the integration tests where their
services are available, and the consumer-module build check. Confirm the root
module's dependency graph contains no Redis client or SQL driver.

No backend is removed and no storage interface changes. SQL constructors move,
so callers using the old import paths must update them.
