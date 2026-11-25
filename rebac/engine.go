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
}

// Option configures an Engine.
type Option func(*Engine)

// WithMaxDepth limits the recursion depth of a check. The default is 50.
func WithMaxDepth(n int) Option { return func(e *Engine) { e.maxDepth = n } }

// WithMaxEvaluations limits the number of relation evaluations per check.
// The default is 10000.
func WithMaxEvaluations(n int) Option { return func(e *Engine) { e.maxEvaluations = n } }

// NewEngine returns an Engine.
func NewEngine(schema *Schema, store TupleStore, opts ...Option) (*Engine, error) {
	if schema == nil || store == nil {
		return nil, errors.New("rebac: nil schema or store")
	}
	e := &Engine{schema: schema, store: store, maxDepth: 50, maxEvaluations: 10000}
	for _, opt := range opts {
		opt(e)
	}
	if e.maxDepth <= 0 || e.maxEvaluations <= 0 {
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
// is still returned as true, since it does not depend on the failing one.
func (e *Engine) Check(ctx context.Context, object Object, permission string, subject Subject) (bool, error) {
	if err := validateObject(object, false); err != nil {
		return false, err
	}
	if err := validateSubject(subject, false); err != nil {
		return false, err
	}
	if _, ok := e.schema.relation(object.Type, permission); !ok {
		return false, fmt.Errorf("%w: %s#%s", ErrUnknownRelation, object.Type, permission)
	}
	c := &checker{
		Engine:  e,
		ctx:     ctx,
		subject: subject,
		onPath:  map[objRel]bool{},
		granted: map[objRel]bool{},
	}
	return c.check(object, permission, 0)
}

// checker evaluates a single Check.
type checker struct {
	*Engine
	ctx     context.Context
	subject Subject

	// onPath holds the relations being evaluated on the current path.
	// Re-entering one is a cycle in the data (such as two groups that
	// contain each other) and contributes nothing, so it evaluates to
	// false.
	onPath map[objRel]bool
	// granted memoizes positive results. Only positive results are cached,
	// because a negative one may be an artifact of a cycle cut-off.
	granted     map[objRel]bool
	evaluations int
}

func (c *checker) check(obj Object, rel string, depth int) (bool, error) {
	if depth > c.maxDepth {
		return false, fmt.Errorf("%w: depth exceeds %d", ErrTooComplex, c.maxDepth)
	}
	if c.evaluations++; c.evaluations > c.maxEvaluations {
		return false, fmt.Errorf("%w: more than %d evaluations", ErrTooComplex, c.maxEvaluations)
	}
	if err := c.ctx.Err(); err != nil {
		return false, err
	}
	// A userset always contains itself: group:eng#member has member on
	// group:eng.
	if c.subject.Relation == rel && c.subject.Object == obj {
		return true, nil
	}
	info, ok := c.schema.relation(obj.Type, rel)
	if !ok {
		// Tuples may outlive schema changes; an undefined relation grants
		// nothing.
		return false, nil
	}
	k := objRel{obj, rel}
	if c.granted[k] {
		return true, nil
	}
	if c.onPath[k] {
		return false, nil
	}
	c.onPath[k] = true
	ok, err := c.eval(obj, rel, info.rewrite, depth)
	delete(c.onPath, k)
	if ok {
		c.granted[k] = true
	}
	return ok, err
}

func (c *checker) eval(obj Object, rel string, r Rewrite, depth int) (bool, error) {
	switch r := r.(type) {
	case direct:
		return c.evalDirect(obj, rel, depth)
	case computed:
		return c.check(obj, r.relation, depth+1)
	case tupleToUserset:
		return c.evalTupleToUserset(obj, r, depth)
	case union:
		return c.any(len(r.children), func(i int) (bool, error) {
			return c.eval(obj, rel, r.children[i], depth)
		})
	case intersection:
		for _, child := range r.children {
			ok, err := c.eval(obj, rel, child, depth)
			if err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	case exclusion:
		ok, err := c.eval(obj, rel, r.base, depth)
		if err != nil || !ok {
			return false, err
		}
		excluded, err := c.eval(obj, rel, r.subtract, depth)
		if err != nil {
			return false, err
		}
		return !excluded, nil
	}
	return false, fmt.Errorf("rebac: unknown rewrite %T", r)
}

// any returns true if any of n branches is true. Errors are only reported
// if no branch grants access.
func (c *checker) any(n int, branch func(int) (bool, error)) (bool, error) {
	var firstErr error
	for i := range n {
		ok, err := branch(i)
		if ok {
			return true, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return false, firstErr
}

func (c *checker) evalDirect(obj Object, rel string, depth int) (bool, error) {
	var usersets []Subject
	for t, err := range c.store.Read(c.ctx, Filter{ObjectType: obj.Type, ObjectID: obj.ID, Relation: rel}) {
		if err != nil {
			return false, fmt.Errorf("rebac: reading tuples: %w", err)
		}
		s := t.Subject
		switch {
		case s == c.subject:
			return true, nil
		case s.isWildcard():
			if c.subject.Relation == "" && c.subject.Object.Type == s.Object.Type {
				return true, nil
			}
		case s.Relation != "":
			usersets = append(usersets, s)
		}
	}
	// Expand usersets only after the cheap direct matches above.
	return c.any(len(usersets), func(i int) (bool, error) {
		return c.check(usersets[i].Object, usersets[i].Relation, depth+1)
	})
}

func (c *checker) evalTupleToUserset(obj Object, r tupleToUserset, depth int) (bool, error) {
	var targets []Object
	for t, err := range c.store.Read(c.ctx, Filter{ObjectType: obj.Type, ObjectID: obj.ID, Relation: r.tupleset}) {
		if err != nil {
			return false, fmt.Errorf("rebac: reading tuples: %w", err)
		}
		if !t.Subject.isWildcard() {
			targets = append(targets, t.Subject.Object)
		}
	}
	return c.any(len(targets), func(i int) (bool, error) {
		return c.check(targets[i], r.computed, depth+1)
	})
}
