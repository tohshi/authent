package rebac

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observe"
)

var (
	// ErrUnknownRelation is returned when an object type or relation is not
	// defined in the schema.
	ErrUnknownRelation = errors.New("rebac: unknown type or relation")
	// ErrSubjectNotAllowed is returned when writing a tuple whose relation
	// is not writable or whose subject type the relation does not allow.
	ErrSubjectNotAllowed = errors.New("rebac: subject not allowed for relation")
	// ErrTooComplex is returned when a check exceeds the depth or
	// evaluation limits. The check fails closed.
	ErrTooComplex = errors.New("rebac: check too complex")
)

// Engine writes tuples and answers permission checks against a Schema.
// It is safe for concurrent use.
type Engine struct {
	schema         *Schema
	store          TupleStore
	maxDepth       int
	maxEvaluations int
	concurrency    int
	watchInterval  time.Duration
	cache          *checkCache
	observer       authent.Observer
}

// Option configures an Engine.
type Option func(*Engine)

// WithMaxDepth limits the recursion depth of a check. The default is 50.
func WithMaxDepth(n int) Option { return func(e *Engine) { e.maxDepth = n } }

// WithObserver sends an Event of kind authent.KindAuthorization to o for
// every check of Check and CheckBulk. A conditional check, one that fails
// with ErrMissingContext, has the Decision authent.DecisionConditional.
func WithObserver(o authent.Observer) Option { return func(e *Engine) { e.observer = o } }

// WithMaxEvaluations limits the number of relation evaluations per check.
// The count is shared by all branches of the check, including those
// evaluated in parallel. A check that exceeds it fails with ErrTooComplex,
// even if a branch evaluated before the limit was reached granted access.
// The default is 10000.
func WithMaxEvaluations(n int) Option { return func(e *Engine) { e.maxEvaluations = n } }

// WithConcurrency lets a call evaluate up to n branches of Union and
// Intersection rewrites, usersets and tuple-to-userset targets, and the
// items of CheckBulk, at the same time. Once a branch decides its parent,
// for example a Union branch that grants, the other branches are
// cancelled. The default, 1, evaluates branches one after another.
//
// Results do not depend on the order in which branches finish. How much of
// the evaluation limit a check uses can, since a cancelled branch may have
// done some work first, so a check close to the limit may succeed in one
// run and fail with ErrTooComplex in another.
func WithConcurrency(n int) Option { return func(e *Engine) { e.concurrency = n } }

// WithCheckCache keeps the results of up to size checks across calls, the
// least recently used dropped first. A cached result answers a check only
// if it was computed at the store's latest revision, which every check
// reads anyway, so any write, a revoke included, takes effect at once. The
// cache saves evaluation, not the revision read. Errors are not cached.
func WithCheckCache(size int) Option {
	return func(e *Engine) {
		e.cache = nil
		if size > 0 {
			e.cache = newCheckCache(size)
		}
	}
}

// WithWatchInterval sets how often Watch asks the store for new changes.
// The default is one second.
func WithWatchInterval(d time.Duration) Option { return func(e *Engine) { e.watchInterval = d } }

// NewEngine returns an Engine.
func NewEngine(schema *Schema, store TupleStore, opts ...Option) (*Engine, error) {
	if schema == nil || store == nil {
		return nil, errors.New("rebac: nil schema or store")
	}
	e := &Engine{schema: schema, store: store, maxDepth: 50, maxEvaluations: 10000, concurrency: 1, watchInterval: time.Second}
	for _, opt := range opts {
		opt(e)
	}
	if e.maxDepth <= 0 || e.maxEvaluations <= 0 || e.concurrency <= 0 || e.watchInterval <= 0 {
		return nil, errors.New("rebac: limits must be positive")
	}
	return e, nil
}

// Write validates the tuples against the schema and applies them
// atomically: deletes first, then writes. It returns the revision of the
// store after the write. Store it with the content the tuples protect and
// pass it to AtLeast when checking access to that content, so the check
// sees the write.
func (e *Engine) Write(ctx context.Context, writes, deletes []Tuple) (Revision, error) {
	writes = slices.Clone(writes)
	for i, t := range writes {
		if err := e.validateWrite(t); err != nil {
			return 0, err
		}
		if t.Caveat.Context != "" {
			c, err := e.schema.caveats[t.Caveat.Name].canonical(t.Caveat.Context)
			if err != nil {
				return 0, fmt.Errorf("%w: %s: caveat context: %v", ErrInvalidTuple, t, err)
			}
			writes[i].Caveat.Context = c
		}
	}
	for _, t := range deletes {
		if err := t.validate(); err != nil {
			return 0, err
		}
	}
	return e.store.Write(ctx, writes, deletes)
}

// QueryOption configures Check, CheckBulk, Expand, ListObjects and
// ListSubjects.
type QueryOption func(*queryConfig)

type queryConfig struct {
	atLeast Revision
	context map[string]any
}

// AtLeast makes a query fail with ErrFutureRevision if the store, such as
// a lagging replica, has not reached revision rev, such as a revision that
// Write returned. Queries always read the store's latest revision; AtLeast
// only detects a store that is behind the caller.
func AtLeast(rev Revision) QueryOption { return func(c *queryConfig) { c.atLeast = rev } }

// Watch yields the changes made after revision after, in the order of
// Changes, as they are written. It asks the store for new changes at the
// interval set by WithWatchInterval and ends when ctx is done, or after
// yielding an error such as ErrRevisionExpired. To resume, pass the
// revision of the last change whose revision you have received in full.
func (e *Engine) Watch(ctx context.Context, after Revision) iter.Seq2[Change, error] {
	return func(yield func(Change, error) bool) {
		t := time.NewTicker(e.watchInterval)
		defer t.Stop()
		for {
			// Changes after the latest revision read before asking cover it,
			// so the cursor can move up to it even when nothing changed.
			latest, err := e.store.Revision(ctx)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				yield(Change{}, err)
				return
			}
			for c, err := range e.store.Changes(ctx, after) {
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					yield(Change{}, err)
					return
				}
				if !yield(c, nil) {
					return
				}
				after = c.Revision
			}
			after = max(after, latest)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}
}

func (e *Engine) validateWrite(t Tuple) error {
	if err := t.validate(); err != nil {
		return err
	}
	info, ok := e.schema.relation(t.Object.Type, t.Relation)
	if !ok {
		return fmt.Errorf("%w: %s#%s", ErrUnknownRelation, t.Object.Type, t.Relation)
	}
	if !info.admits(t) {
		return fmt.Errorf("%w: %s", ErrSubjectNotAllowed, t)
	}
	return nil
}

func (e *Engine) validateQuerySubject(s Subject) error {
	if err := validateSubject(s, false); err != nil {
		return err
	}
	if s.Relation != "" {
		if _, ok := e.schema.relation(s.Object.Type, s.Relation); !ok {
			return fmt.Errorf("%w: subject %s", ErrUnknownRelation, s)
		}
	}
	return nil
}

// Check reports whether subject has permission (a relation) on object.
//
// Errors fail closed: if any branch needed to decide the result errors,
// Check returns false and the error. A grant found through another branch
// is still returned as true, since it does not depend on the failing one,
// and so is a denial decided by another branch, such as an Intersection
// operand that is false.
//
// Cycles in the data are evaluated with the well-founded semantics of the
// rewrite rules. A cycle never grants by itself: groups that only contain
// each other have no members, and a cycle cannot cancel the subtraction of
// an Exclusion. A relation that depends on its own exclusion and is not
// decided by anything else has no answer; Check returns false with
// ErrExclusionCycle.
//
// All reads of a check are at one revision of the store, the latest.
func (e *Engine) Check(ctx context.Context, object Object, permission string, subject Subject, opts ...QueryOption) (bool, error) {
	r := e.newRequest(ctx, opts).check(CheckItem{Object: object, Permission: permission, Subject: subject})
	return r.Allowed, r.Err
}

// CheckItem is one check of a CheckBulk call.
type CheckItem struct {
	Object     Object
	Permission string
	Subject    Subject
}

// CheckResult is the result of one CheckItem: the values Check would
// return for it.
type CheckResult struct {
	Allowed bool
	Err     error
}

// CheckBulk runs many checks in one call and returns their results in the
// order of items. The checks share the tuples they read from the store and,
// when they are about the same subject, the relations they decide on the
// way, and read one revision of the store. Each check has its own
// evaluation limit and its own error. CheckBulk returns an error only if
// the store's revision cannot be read or is older than AtLeast asks.
func (e *Engine) CheckBulk(ctx context.Context, items []CheckItem, opts ...QueryOption) ([]CheckResult, error) {
	q := e.newRequest(ctx, opts)
	out := make([]CheckResult, len(items))
	q.spread(len(items), func(i int) { out[i] = q.check(items[i]) })
	if q.revErr != nil {
		return nil, q.revErr
	}
	return out, nil
}

func (q *request) check(it CheckItem) CheckResult {
	start := observe.Start(q.e.observer)
	res, evals := q.decide(it)
	if q.e.observer != nil {
		ev := authent.Event{
			Kind:        authent.KindAuthorization,
			Outcome:     authent.OutcomeSuccess,
			ObjectType:  it.Object.Type,
			Relation:    it.Permission,
			Evaluations: evals,
			Duration:    time.Since(start),
		}
		switch {
		case res.Err == nil && res.Allowed:
			ev.Decision = authent.DecisionAllowed
		case res.Err == nil:
			ev.Decision = authent.DecisionDenied
		case errors.Is(res.Err, ErrMissingContext):
			ev.Decision = authent.DecisionConditional
		default:
			ev.Outcome, ev.Reason = authent.OutcomeError, observe.ReasonOf(res.Err)
		}
		observe.Emit(q.ctx, q.e.observer, ev)
	}
	return res
}

func (q *request) decide(it CheckItem) (res CheckResult, evals int) {
	if err := validateObject(it.Object, false); err != nil {
		return CheckResult{Err: err}, 0
	}
	if err := q.e.validateQuerySubject(it.Subject); err != nil {
		return CheckResult{Err: err}, 0
	}
	if _, ok := q.e.schema.relation(it.Object.Type, it.Permission); !ok {
		return CheckResult{Err: fmt.Errorf("%w: %s#%s", ErrUnknownRelation, it.Object.Type, it.Permission)}, 0
	}
	// A result that depends on the request's caveat context is not
	// reusable by other requests.
	cache := q.e.cache
	if len(q.cfg.context) > 0 {
		cache = nil
	}
	rev, err := q.revision()
	if err != nil {
		return CheckResult{Err: err}, 0
	}
	if cache != nil {
		if allowed, ok := cache.get(it, rev); ok {
			return CheckResult{Allowed: allowed}, 0
		}
	}

	r := &run{request: q, subject: it.Subject}
	f := r.check(q.ctx, nil, it.Object, it.Permission).f
	evals = int(r.evals.Load())
	if r.exceeded() {
		return CheckResult{Err: r.errTooComplex()}, evals
	}
	switch f.op {
	case opTrue, opFalse:
		if cache != nil {
			cache.put(it, rev, f.op == opTrue)
		}
		return CheckResult{Allowed: f.op == opTrue}, evals
	case opUnknown:
		return CheckResult{Err: f.why}, evals
	}
	return CheckResult{}, evals
}

func init() {
	observe.Register(map[error]authent.Reason{
		ErrUnknownRelation: authent.ReasonUnknownRelation,
		ErrTooComplex:      authent.ReasonTooComplex,
		ErrExclusionCycle:  authent.ReasonCycle,
		ErrFutureRevision:  authent.ReasonFutureRevision,
		ErrRevisionExpired: authent.ReasonRevisionExpired,
		ErrInvalidTuple:    authent.ReasonInvalidInput,
	})
}
