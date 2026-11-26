package rebac

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
)

type request struct {
	e     *Engine
	ctx   context.Context
	cfg   queryConfig
	slots chan struct{} // nil, so never ready, without WithConcurrency

	revOnce sync.Once
	rev     Revision
	revErr  error

	mu    sync.Mutex
	reads map[objRel]*read
	memo  map[memoKey]bool
}

type read struct {
	done      chan struct{}
	tuples    []Tuple
	err       error
	abandoned bool
}

type memoKey struct {
	subject Subject
	at      objRel
}

func (e *Engine) newRequest(ctx context.Context, opts []QueryOption) *request {
	q := &request{e: e, ctx: ctx, reads: map[objRel]*read{}, memo: map[memoKey]bool{}}
	for _, opt := range opts {
		opt(&q.cfg)
	}
	if e.concurrency > 1 {
		q.slots = make(chan struct{}, e.concurrency-1)
	}
	return q
}

func (q *request) revision() (Revision, error) {
	q.revOnce.Do(func() {
		q.rev, q.revErr = q.e.store.Revision(q.ctx)
		if q.revErr == nil && q.rev < q.cfg.atLeast {
			q.revErr = fmt.Errorf("%w: %d is after %d", ErrFutureRevision, q.cfg.atLeast, q.rev)
		}
	})
	return q.rev, q.revErr
}

// read returns the tuples of obj#rel. A pair is read from the store once
// per request, unless the branch reading it is cancelled; then the next
// reader reads it again.
func (q *request) read(ctx context.Context, obj Object, rel string) ([]Tuple, error) {
	k := objRel{obj, rel}
	for {
		q.mu.Lock()
		r, ok := q.reads[k]
		if !ok {
			r = &read{done: make(chan struct{})}
			q.reads[k] = r
		}
		q.mu.Unlock()

		if !ok {
			r.tuples, r.err = q.fetch(ctx, k)
			if r.err != nil && ctx.Err() != nil {
				r.abandoned = true
				q.mu.Lock()
				delete(q.reads, k)
				q.mu.Unlock()
			}
			close(r.done)
			return r.tuples, r.err
		}
		select {
		case <-r.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if !r.abandoned {
			return r.tuples, r.err
		}
	}
}

func (q *request) fetch(ctx context.Context, k objRel) ([]Tuple, error) {
	rev, err := q.revision()
	if err != nil {
		return nil, err
	}
	var out []Tuple
	for t, err := range q.e.store.Read(ctx, rev, Filter{ObjectType: k.obj.Type, ObjectID: k.obj.ID, Relation: k.rel}) {
		if err != nil {
			return nil, fmt.Errorf("rebac: reading tuples: %w", err)
		}
		out = append(out, t)
	}
	// A store may end a read early, without an error, once ctx is done.
	// Such a read is incomplete and must not be cached or decide anything.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (q *request) spread(n int, f func(i int)) {
	var wg sync.WaitGroup
	for i := range n {
		select {
		case q.slots <- struct{}{}:
			wg.Go(func() {
				defer func() { <-q.slots }()
				f(i)
			})
		default:
			f(i)
		}
	}
	wg.Wait()
}

// branches evaluates n branches. Once one returns decides, the others are
// cancelled and no new ones start.
func (q *request) branches(ctx context.Context, n int, decides formulaOp, f func(context.Context, int) result) []result {
	out := make([]result, 0, n)
	if q.slots == nil || n < 2 {
		for i := range n {
			r := f(ctx, i)
			out = append(out, r)
			if r.f.op == decides {
				break
			}
		}
		return out
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	out = out[:n]
	started := 0
	var wg sync.WaitGroup
	for i := range n {
		if ctx.Err() != nil {
			break
		}
		started++
		run := func() {
			out[i] = f(ctx, i)
			if out[i].f.op == decides {
				cancel()
			}
		}
		select {
		case q.slots <- struct{}{}:
			wg.Go(func() {
				defer func() { <-q.slots }()
				run()
			})
		default:
			run()
		}
	}
	wg.Wait()
	out = out[:started]
	if started < n && !slices.ContainsFunc(out, func(r result) bool { return r.f.op == decides }) {
		out = append(out, resUnknown(context.Cause(ctx)))
	}
	return out
}

// run evaluates one CheckItem. Its evaluation count is shared by all of
// its branches.
type run struct {
	*request
	subject Subject
	evals   atomic.Int64
}

func (r *run) exceeded() bool { return r.evals.Load() > int64(r.e.maxEvaluations) }

func (r *run) errTooComplex() error {
	return fmt.Errorf("%w: more than %d evaluations", ErrTooComplex, r.e.maxEvaluations)
}

func (r *run) recall(a objRel) (*formula, bool) {
	r.mu.Lock()
	v, ok := r.memo[memoKey{r.subject, a}]
	r.mu.Unlock()
	if !ok {
		return nil, false
	}
	return resBool(v).f, true
}

// remember stores a true or false value. Unknown values are not stored:
// their causes, such as a cancelled branch or the depth limit, depend on
// the branch and path that met them.
func (r *run) remember(a objRel, f *formula) {
	if f.op != opTrue && f.op != opFalse {
		return
	}
	r.mu.Lock()
	r.memo[memoKey{r.subject, a}] = f.op == opTrue
	r.mu.Unlock()
}

type path struct {
	at     objRel
	parent *path
	depth  int
}

func (p *path) next() int {
	if p == nil {
		return 0
	}
	return p.depth + 1
}

func (p *path) find(a objRel) (depth int, ok bool) {
	for ; p != nil; p = p.parent {
		if p.at == a {
			return p.depth, true
		}
	}
	return 0, false
}

// An atom that is reached again while it is being evaluated is a cycle in
// the data. Its value is then not known yet, so check returns a reference
// to it. When the evaluation of an atom finishes and refers to no atom
// further up the path, the atom and every undecided atom below it form a
// closed system of equations, which solve decides.
func (r *run) check(ctx context.Context, parent *path, obj Object, rel string) result {
	depth := parent.next()
	if depth > r.e.maxDepth {
		return resUnknown(fmt.Errorf("%w: depth exceeds %d", ErrTooComplex, r.e.maxDepth))
	}
	if r.evals.Add(1) > int64(r.e.maxEvaluations) {
		return resUnknown(r.errTooComplex())
	}
	if err := ctx.Err(); err != nil {
		return resUnknown(err)
	}
	if r.subject.Relation == rel && r.subject.Object == obj {
		return resTrue
	}
	info, ok := r.e.schema.relation(obj.Type, rel)
	if !ok {
		// Tuples may outlive schema changes; an undefined relation grants
		// nothing.
		return resFalse
	}
	a := objRel{obj, rel}
	if f, ok := r.recall(a); ok {
		return decided(f)
	}
	if d, ok := parent.find(a); ok {
		return result{f: &formula{op: opRef, ref: a}, minDepth: d}
	}

	res := r.eval(ctx, &path{at: a, parent: parent, depth: depth}, obj, rel, info.rewrite)
	if res.f.decided() {
		r.remember(a, res.f)
		return decided(res.f)
	}
	if res.eqs == nil {
		res.eqs = map[objRel]*formula{}
	}
	res.eqs[a] = res.f
	if res.minDepth < depth {
		return result{f: &formula{op: opRef, ref: a}, minDepth: res.minDepth, eqs: res.eqs}
	}
	vals := solve(res.eqs)
	for at, f := range vals {
		r.remember(at, f)
	}
	return decided(vals[a])
}

func (r *run) eval(ctx context.Context, p *path, obj Object, rel string, rw Rewrite) result {
	switch rw := rw.(type) {
	case direct:
		return r.direct(ctx, p, obj, rel)
	case computed:
		return r.check(ctx, p, obj, rw.relation)
	case tupleToUserset:
		return r.tupleToUserset(ctx, p, obj, rw)
	case union:
		return join(opOr, r.branches(ctx, len(rw.children), opTrue, func(ctx context.Context, i int) result {
			return r.eval(ctx, p, obj, rel, rw.children[i])
		}))
	case intersection:
		return join(opAnd, r.branches(ctx, len(rw.children), opFalse, func(ctx context.Context, i int) result {
			return r.eval(ctx, p, obj, rel, rw.children[i])
		}))
	case exclusion:
		base := r.eval(ctx, p, obj, rel, rw.base)
		if base.f.op == opFalse {
			return base
		}
		return join(opAnd, []result{base, negate(r.eval(ctx, p, obj, rel, rw.subtract))})
	}
	return resUnknown(fmt.Errorf("rebac: unknown rewrite %T", rw))
}

func (r *run) direct(ctx context.Context, p *path, obj Object, rel string) result {
	tuples, err := r.read(ctx, obj, rel)
	if err != nil {
		return resUnknown(err)
	}
	var matches []result
	var usersets []Tuple
	for _, t := range tuples {
		s := t.Subject
		switch {
		case s == r.subject || s.isWildcard() && r.subject.Relation == "" && r.subject.Object.Type == s.Object.Type:
			if t.Caveat.Name == "" {
				return resTrue
			}
			matches = append(matches, r.caveat(t.Caveat))
		case s.Relation != "" && !s.isWildcard():
			usersets = append(usersets, t)
		}
	}
	if m := join(opOr, matches); m.f.op == opTrue {
		return m
	}
	return join(opOr, append(matches, r.branches(ctx, len(usersets), opTrue, func(ctx context.Context, i int) result {
		u := usersets[i]
		return r.conditional(u.Caveat, func() result { return r.check(ctx, p, u.Subject.Object, u.Subject.Relation) })
	})...))
}

func (r *run) tupleToUserset(ctx context.Context, p *path, obj Object, rw tupleToUserset) result {
	tuples, err := r.read(ctx, obj, rw.tupleset)
	if err != nil {
		return resUnknown(err)
	}
	var targets []Tuple
	for _, t := range tuples {
		if !t.Subject.isWildcard() {
			targets = append(targets, t)
		}
	}
	return join(opOr, r.branches(ctx, len(targets), opTrue, func(ctx context.Context, i int) result {
		t := targets[i]
		return r.conditional(t.Caveat, func() result { return r.check(ctx, p, t.Subject.Object, rw.computed) })
	}))
}
