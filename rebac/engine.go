package rebac

import (
	"context"
	"errors"
	"fmt"
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
}

// Option configures an Engine.
type Option func(*Engine)

// WithMaxDepth limits the recursion depth of a check. The default is 50.
func WithMaxDepth(n int) Option { return func(e *Engine) { e.maxDepth = n } }

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

// NewEngine returns an Engine.
func NewEngine(schema *Schema, store TupleStore, opts ...Option) (*Engine, error) {
	if schema == nil || store == nil {
		return nil, errors.New("rebac: nil schema or store")
	}
	e := &Engine{schema: schema, store: store, maxDepth: 50, maxEvaluations: 10000, concurrency: 1}
	for _, opt := range opts {
		opt(e)
	}
	if e.maxDepth <= 0 || e.maxEvaluations <= 0 || e.concurrency <= 0 {
		return nil, errors.New("rebac: limits must be positive")
	}
	return e, nil
}

// Write validates the tuples against the schema and applies them
// atomically: deletes first, then writes.
func (e *Engine) Write(ctx context.Context, writes, deletes []Tuple) error {
	for _, t := range writes {
		if err := e.validateWrite(t); err != nil {
			return err
		}
	}
	for _, t := range deletes {
		if err := t.validate(); err != nil {
			return err
		}
	}
	return e.store.Write(ctx, writes, deletes)
}

func (e *Engine) validateWrite(t Tuple) error {
	if err := t.validate(); err != nil {
		return err
	}
	info, ok := e.schema.relation(t.Object.Type, t.Relation)
	if !ok {
		return fmt.Errorf("%w: %s#%s", ErrUnknownRelation, t.Object.Type, t.Relation)
	}
	for _, a := range info.allowed {
		if a.matches(t.Subject) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrSubjectNotAllowed, t)
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
func (e *Engine) Check(ctx context.Context, object Object, permission string, subject Subject) (bool, error) {
	r := e.newRequest(ctx).check(CheckItem{Object: object, Permission: permission, Subject: subject})
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
// way. Each check has its own evaluation limit and its own error.
func (e *Engine) CheckBulk(ctx context.Context, items []CheckItem) []CheckResult {
	q := e.newRequest(ctx)
	out := make([]CheckResult, len(items))
	q.spread(len(items), func(i int) { out[i] = q.check(items[i]) })
	return out
}

func (q *request) check(it CheckItem) CheckResult {
	if err := validateObject(it.Object, false); err != nil {
		return CheckResult{Err: err}
	}
	if err := validateSubject(it.Subject, false); err != nil {
		return CheckResult{Err: err}
	}
	if _, ok := q.e.schema.relation(it.Object.Type, it.Permission); !ok {
		return CheckResult{Err: fmt.Errorf("%w: %s#%s", ErrUnknownRelation, it.Object.Type, it.Permission)}
	}
	r := &run{request: q, subject: it.Subject}
	res := r.check(q.ctx, nil, it.Object, it.Permission)
	if r.exceeded() {
		return CheckResult{Err: r.errTooComplex()}
	}
	switch res.f.op {
	case opTrue:
		return CheckResult{Allowed: true}
	case opUnknown:
		return CheckResult{Err: res.f.why}
	}
	return CheckResult{}
}
