# ReBAC

[← authent README](../README.md)

```go
schema, _ := rebac.NewSchema(
	rebac.Type("user"),
	rebac.Type("group", rebac.Relation("member", rebac.Direct("user", "group#member"))),
	rebac.Type("folder",
		rebac.Relation("owner", rebac.Direct("user")),
		rebac.Relation("viewer", rebac.Union(rebac.Direct("user", "group#member", "user:*"), rebac.Computed("owner"))),
	),
	rebac.Type("doc",
		rebac.Relation("parent", rebac.Direct("folder")),
		rebac.Relation("banned", rebac.Direct("user")),
		rebac.Relation("viewer", rebac.Exclusion(
			rebac.Union(rebac.Direct("user"), rebac.TupleToUserset("parent", "viewer")),
			rebac.Computed("banned"))),
	),
)
engine, _ := rebac.NewEngine(schema, rebac.NewMemoryStore())
rev, err := engine.Write(ctx, []rebac.Tuple{
	rebac.MustParseTuple("folder:root#viewer@group:eng#member"),
	rebac.MustParseTuple("doc:readme#parent@folder:root"),
}, nil)
// Store rev with the document. AtLeast(rev) makes the check fail rather
// than read a store that has not seen the write.
ok, err := engine.Check(ctx, rebac.Obj("doc", "readme"), "viewer", rebac.Sub("user", "alice"), rebac.AtLeast(rev))
```
- Writes that do not match the schema are rejected. Examples are a subject
  type the relation does not allow, or a write to a computed-only relation.
- Every query reads stored tuples through the current schema. After a
  schema change, a tuple the relation no longer allows (a subject type,
  userset, wildcard or caveat that was removed) grants nothing in `Check`,
  `CheckBulk`, `ListObjects`, `ListSubjects` and `Expand`. A query subject
  such as `team:t#viewer` whose relation the schema does not define fails
  with `ErrUnknownRelation`.
- Relations that depend on themselves through `Computed` alone are rejected
  when the schema is built.
- Cycles in the data follow the well-founded semantics of the rewrites. A
  cycle never grants by itself: groups that only contain each other have
  no members, and a cycle cannot cancel the subtraction of an
  `Exclusion`. A relation that depends on its own exclusion ("viewers are
  the users who are not viewers") has no answer, and `Check` fails closed
  with `ErrExclusionCycle`.
- Depth and evaluation count are bounded. Exceeding either limit returns
  `false` with `ErrTooComplex`.
- Store errors fail closed: `Check` returns `false` with the error.
- Every `Write` moves the store to a new `Revision`, Zanzibar's consistency
  token ("zookie"). A query reads one revision, the latest, so it never
  mixes data from before and after a write. `AtLeast(rev)` makes a query
  fail with `ErrFutureRevision` if the store has not reached `rev`, such as
  a replica that is behind.
- `TupleStore.Changes` lists the writes and deletes after a revision, and
  `Engine.Watch` streams them as they happen. `Prune` on `MemoryStore` and
  `SQLStore` discards history; reads and changes before the pruned
  revision then fail with `ErrRevisionExpired`.
- `WithCheckCache(n)` keeps up to `n` check results across calls. A result
  answers a later check only if it was computed at the store's latest
  revision, which every check reads, so a revoke takes effect at once.
  Errors are not cached.
- `ListObjects(ctx, "doc", "viewer", subject)` lists the documents a
  subject can view; `ListSubjects(ctx, doc, "viewer", "user")` lists who
  can view a document, or with a wildcard, everyone except some users. Both
  find candidates by walking the tuples and then check each one, so they
  agree with `Check` under every rewrite. They are bounded by the
  evaluation limit and honor cancellation.
- `CheckBulk` runs many checks in one call. They share store reads and
  the relations they decide on the way; results come back in order, each
  with its own error.
- `Expand` returns the userset tree of an `object#relation`: union,
  intersection and exclusion nodes down to the subjects of tuples. It
  follows `Computed` and `TupleToUserset`; usersets named by tuples, such
  as `group:eng#member`, are leaves to expand with another call.
- `WithConcurrency(n)` evaluates up to `n` branches of a check (and items
  of `CheckBulk`) in parallel, which helps with network stores. Once a
  branch decides, its siblings are cancelled. The evaluation limit is
  shared by all branches: a check that exceeds it fails, even if a branch
  granted first.

To check permissions for an authenticated request, map its Principal to a
subject:
```go
sub, err := rebac.SubjectOf(p, "user") // user:<p.Subject>; an empty or "*" subject is an error
ok, err := engine.Check(ctx, rebac.Obj("doc", id), "viewer", sub)

// or as middleware, inside httpauth.Require:
mux.Handle("GET /docs/{id}", httpauth.Require(auth)(
	httpauth.RequirePermission(engine, "viewer", "user", func(r *http.Request) (rebac.Object, error) {
		return rebac.Obj("doc", r.PathValue("id")), nil
	})(docHandler)))
```
`RequirePermission` responds 403 when the check is denied or the object
ID is invalid, and 500 when the check fails.

## Text schemas
```go
schema, err := rebac.ParseSchema(`
type user
type group {
	relation member: [user, group#member]
}
type doc {
	relation banned: [user]
	relation viewer: [user, group#member, user:*] but not banned
}`, nil) // a map of caveat functions, if the text declares caveats
fmt.Print(schema) // the same schema in canonical form
```
- The text maps one to one onto the Go API: `[types]` is `Direct`, a
  relation name is `Computed`, `a from b` is `TupleToUserset(b, a)`, and
  `or`, `and` and `but not` are `Union`, `Intersection` and `Exclusion`.
  Mixing operators needs parentheses. `caveat name(p type, ...)` declares
  a caveat whose function comes from the map.
- Errors are `*ParseError` values with a line and column, also for
  problems found when validating, such as an unknown relation.
- `Schema.String` writes the canonical form, which parses back to the same
  schema.
- The text and the Go API accept the same schemas. Names cannot be the
  keywords `type`, `relation`, `caveat`, `or`, `and`, `but`, `not`, `from`
  and `with`, and `NewSchema` rejects them too. Operators nest at most 64
  deep, so text allows 63 levels of parentheses.

## Caveats
```go
schema, _ := rebac.NewSchema(
	rebac.Caveat("office", func(args map[string]any) (bool, error) {
		ip, err := netip.ParseAddr(args["ip"].(string))
		return err == nil && netip.MustParsePrefix(args["cidr"].(string)).Contains(ip), err
	}, rebac.Param{Name: "cidr", Type: rebac.ParamString}, rebac.Param{Name: "ip", Type: rebac.ParamString}),
	rebac.Type("user"),
	rebac.Type("doc", rebac.Relation("viewer", rebac.Direct("user", "user with office"))),
)
engine.Write(ctx, []rebac.Tuple{
	rebac.MustParseTuple(`doc:readme#viewer@user:bob[office:{"cidr":"10.0.0.0/8"}]`),
}, nil)
ok, err := engine.Check(ctx, rebac.Obj("doc", "readme"), "viewer", rebac.Sub("user", "bob"),
	rebac.WithContext(map[string]any{"ip": clientIP}))
```
- A caveat is a Go function of typed parameters (`ParamString`, `ParamInt`,
  `ParamBool`, `ParamTimestamp`, `ParamDuration`, `ParamStringList`); there
  is no expression language. A relation accepts tuples with a caveat only
  through an allowed type such as `"user with office"`.
- A tuple stores values for some parameters as a JSON object, which
  `Write` checks against the parameter types and stores in canonical
  form. Each value must be a JSON value of its type, never `null`: an int
  is a number without fraction or exponent, a duration is a string as
  `time.Duration.String` formats it (`"1h30m0s"`), and a timestamp is an
  RFC 3339 string in UTC as `time.RFC3339Nano` formats it. Stored values
  are read with the same rules, so a value that bypassed `Write` fails the
  check. `WithContext` supplies the others; stored values win, so a request
  cannot override them.
- A check that needs a parameter nobody supplied is conditional: it
  returns `false` with a `*MissingContextError` that names the parameters
  (`errors.Is(err, rebac.ErrMissingContext)`). It is never `true`. Unions,
  intersections and exclusions combine true, false and conditional in
  three-valued logic: a union with a true branch is true, an intersection
  with a false operand is false, anything else that depends on a
  conditional value is conditional.
- A wrong type in the context, an error or a panic in the function fails
  the check closed. `ListObjects` and `ListSubjects` do not list
  conditional results. The check cache skips checks that pass a context.
- Object and subject IDs may not contain `[` or `]`, which delimit the
  caveat in the tuple string format.

## Persistent tuple storage
```go
import _ "github.com/jackc/pgx/v5/stdlib" // or any database/sql driver

db, _ := sql.Open("pgx", dsn)
store, _ := rebac.NewSQLStore(db, rebac.PostgreSQL) // also rebac.MySQL, rebac.SQLite
store.CreateTable(ctx) // or apply store.CreateTableStatements() with your migration tool
engine, _ := rebac.NewEngine(schema, store)
```
- `SQLStore` works through `database/sql` and imports no driver; you choose
  one.
- Identifiers are compared byte by byte. `CreateTable` uses `COLLATE "C"`
  on PostgreSQL and `VARBINARY` on MySQL, so `Alice` and `alice` are
  different subjects whatever the server collation. Rows that do not
  exactly match a lookup are discarded anyway, and rows that are not valid
  tuples make the read fail.
- A write is one transaction. It locks the row of the `<table>_revision`
  table that holds the latest revision, so writes are serialized and
  revisions follow commit order. A delete keeps the row with the revision
  it was deleted at, for reads at older revisions and for `Changes`, until
  `Prune` removes it.
- A read releases its connection before returning tuples, so a pool with a
  single connection (common for SQLite) does not deadlock on recursive
  checks. It reads the latest and the pruned revision in the same
  statement, so a concurrent `Prune` is detected, not silently read
  around.
- `rebactest.TestTupleStore` is a conformance suite for `TupleStore`
  implementations. Run it against your own store, or against `SQLStore`
  with your database and driver.
