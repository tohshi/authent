package rebac

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// typeRel names a relation of a type, or with an empty rel, a plain object
// of the type.
type typeRel struct{ typ, rel string }

// reverseEdge says that a member of some typeRel can be a member of the
// relation rel of objects of type typ.
type reverseEdge struct {
	kind     edgeKind
	typ      string
	rel      string
	tupleset string // edgeTupleset
}

type edgeKind int

const (
	edgeDirect   edgeKind = iota // through a tuple of typ#rel naming the member
	edgeWildcard                 // through a tuple of typ#rel naming the member's type:*
	edgeComputed                 // on the same object
	edgeTupleset                 // through a tuple of typ#tupleset naming the object
)

// reverseEdges returns, for every typeRel, the relations its members can
// reach. Only the base of an Exclusion is followed: the subtracted side
// never adds members.
func (s *Schema) reverseEdges() map[typeRel][]reverseEdge {
	out := map[typeRel][]reverseEdge{}
	add := func(k typeRel, e reverseEdge) {
		if !slices.Contains(out[k], e) {
			out[k] = append(out[k], e)
		}
	}
	// A Direct rewrite reads every tuple of its relation, so a relation with
	// one outside a subtracted side takes in every subject it allows.
	var walk func(typ, rel string, r Rewrite) (direct bool)
	walk = func(typ, rel string, r Rewrite) bool {
		switch r := r.(type) {
		case direct:
			return true
		case computed:
			add(typeRel{typ, r.relation}, reverseEdge{kind: edgeComputed, typ: typ, rel: rel})
		case tupleToUserset:
			ts, _ := s.relation(typ, r.tupleset)
			for _, a := range ts.allowed {
				if _, ok := s.relation(a.typ, r.computed); ok {
					add(typeRel{a.typ, r.computed}, reverseEdge{kind: edgeTupleset, typ: typ, rel: rel, tupleset: r.tupleset})
				}
			}
		case union:
			return walkAll(typ, rel, r.children, walk)
		case intersection:
			return walkAll(typ, rel, r.children, walk)
		case exclusion:
			return walk(typ, rel, r.base)
		}
		return false
	}
	for typ, rels := range s.types {
		for rel, info := range rels {
			if !walk(typ, rel, info.rewrite) {
				continue
			}
			for _, a := range info.allowed {
				if a.wildcard {
					add(typeRel{a.typ, ""}, reverseEdge{kind: edgeWildcard, typ: typ, rel: rel})
				} else {
					add(typeRel{a.typ, a.relation}, reverseEdge{kind: edgeDirect, typ: typ, rel: rel})
				}
			}
		}
	}
	return out
}

func walkAll(typ, rel string, children []Rewrite, walk func(string, string, Rewrite) bool) bool {
	direct := false
	for _, c := range children {
		direct = walk(typ, rel, c) || direct
	}
	return direct
}

// ListObjects returns the objects of objectType on which subject has
// permission, sorted by ID: exactly those for which Check returns true.
//
// It walks from the subject through tuples that name it, and the usersets
// those name in turn, to find candidates, and then checks each one, so it
// is correct under every rewrite. The walk is bounded by the evaluation
// limit and each candidate's check by the limits of Check. An object
// whose check fails with ErrExclusionCycle is not listed; any other error
// fails the call. The whole call reads one revision of the store.
func (e *Engine) ListObjects(ctx context.Context, objectType, permission string, subject Subject, opts ...QueryOption) ([]Object, error) {
	if _, ok := e.schema.relation(objectType, permission); !ok {
		return nil, fmt.Errorf("%w: %s#%s", ErrUnknownRelation, objectType, permission)
	}
	if err := validateSubject(subject, false); err != nil {
		return nil, err
	}
	q := e.newRequest(ctx, opts)
	rev, err := q.revision()
	if err != nil {
		return nil, err
	}
	start := objRel{subject.Object, subject.Relation}
	seen := map[objRel]bool{start: true}
	queue := []objRel{start}
	var candidates []Object
	push := func(n objRel) {
		if !seen[n] {
			seen[n] = true
			queue = append(queue, n)
		}
	}
	for steps := 0; len(queue) > 0; steps++ {
		if steps >= e.maxEvaluations {
			return nil, fmt.Errorf("%w: more than %d evaluations", ErrTooComplex, e.maxEvaluations)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := queue[0]
		queue = queue[1:]
		if n.obj.Type == objectType && n.rel == permission {
			candidates = append(candidates, n.obj)
		}
		for _, ed := range e.schema.reverse[typeRel{n.obj.Type, n.rel}] {
			var f Filter
			switch ed.kind {
			case edgeComputed:
				push(objRel{n.obj, ed.rel})
				continue
			case edgeDirect:
				f = Filter{ObjectType: ed.typ, Relation: ed.rel, Subject: &Subject{n.obj, n.rel}}
			case edgeWildcard:
				f = Filter{ObjectType: ed.typ, Relation: ed.rel, Subject: &Subject{Obj(n.obj.Type, Wildcard), ""}}
			case edgeTupleset:
				f = Filter{ObjectType: ed.typ, Relation: ed.tupleset, Subject: &Subject{Object: n.obj}}
			}
			for t, err := range e.store.Read(ctx, rev, f) {
				if err != nil {
					return nil, fmt.Errorf("rebac: reading tuples: %w", err)
				}
				push(objRel{t.Object, ed.rel})
			}
		}
	}

	slices.SortFunc(candidates, func(a, b Object) int { return strings.Compare(a.ID, b.ID) })
	results := make([]CheckResult, len(candidates))
	q.spread(len(candidates), func(i int) {
		results[i] = q.check(CheckItem{Object: candidates[i], Permission: permission, Subject: subject})
	})
	var out []Object
	for i, r := range results {
		if err := listed(r); err != nil {
			return nil, err
		}
		if r.Allowed {
			out = append(out, candidates[i])
		}
	}
	return out, nil
}

// listed returns the error that fails a list call for a check result.
func listed(r CheckResult) error {
	if r.Err != nil && !errors.Is(r.Err, ErrExclusionCycle) {
		return r.Err
	}
	return nil
}

// SubjectSet is the result of ListSubjects.
type SubjectSet struct {
	// All reports that every subject of the type has the permission,
	// except those in Except. It is set when a wildcard such as user:*
	// grants it.
	All bool
	// Subjects holds the subjects that have the permission when All is
	// false, sorted.
	Subjects []Subject
	// Except holds the subjects that do not have it when All is true,
	// sorted.
	Except []Subject
}

// Contains reports whether subject has the permission.
func (s SubjectSet) Contains(subject Subject) bool {
	if s.All {
		return !slices.Contains(s.Except, subject)
	}
	return slices.Contains(s.Subjects, subject)
}

// ListSubjects returns the subjects of subjectType that have permission on
// object: exactly those for which Check returns true. subjectType is an
// object type, such as "user", or a userset type, such as "group#member".
//
// It walks every relation that object#permission is computed from to find
// the subjects that tuples name, and then checks each one, and one subject
// that no tuple names to see whether a wildcard grants everybody else. It
// is bounded and fails like ListObjects.
func (e *Engine) ListSubjects(ctx context.Context, object Object, permission, subjectType string, opts ...QueryOption) (SubjectSet, error) {
	if err := validateObject(object, false); err != nil {
		return SubjectSet{}, err
	}
	if _, ok := e.schema.relation(object.Type, permission); !ok {
		return SubjectSet{}, fmt.Errorf("%w: %s#%s", ErrUnknownRelation, object.Type, permission)
	}
	want, err := e.schema.parseAllowed(subjectType)
	if err != nil || want.wildcard {
		return SubjectSet{}, fmt.Errorf("%w: subject type %q", ErrUnknownRelation, subjectType)
	}
	q := e.newRequest(ctx, opts)
	if _, err := q.revision(); err != nil {
		return SubjectSet{}, err
	}

	matches := func(s Subject) bool {
		return s.Object.Type == want.typ && s.Relation == want.relation && !s.isWildcard()
	}
	start := objRel{object, permission}
	seen := map[objRel]bool{start: true}
	queue := []objRel{start}
	named := map[Subject]bool{}
	push := func(n objRel) {
		if !seen[n] {
			seen[n] = true
			queue = append(queue, n)
		}
	}
	for steps := 0; len(queue) > 0; steps++ {
		if steps >= e.maxEvaluations {
			return SubjectSet{}, fmt.Errorf("%w: more than %d evaluations", ErrTooComplex, e.maxEvaluations)
		}
		if err := ctx.Err(); err != nil {
			return SubjectSet{}, err
		}
		n := queue[0]
		queue = queue[1:]
		if s := (Subject{n.obj, n.rel}); matches(s) {
			named[s] = true
		}
		info, ok := e.schema.relation(n.obj.Type, n.rel)
		if !ok {
			continue
		}
		if err := q.forEachEdge(n, info.rewrite, func(s Subject) {
			if matches(s) {
				named[s] = true
			}
		}, push); err != nil {
			return SubjectSet{}, err
		}
	}

	candidates := make([]Subject, 0, len(named)+1)
	for s := range named {
		candidates = append(candidates, s)
	}
	slices.SortFunc(candidates, func(a, b Subject) int { return strings.Compare(a.String(), b.String()) })
	if want.relation == "" {
		// A subject that no tuple names is granted only through
		// wildcards, like every other such subject.
		candidates = append(candidates, Sub(want.typ, unnamedID(named)))
	}
	results := make([]CheckResult, len(candidates))
	q.spread(len(candidates), func(i int) {
		results[i] = q.check(CheckItem{Object: object, Permission: permission, Subject: candidates[i]})
	})
	for _, r := range results {
		if err := listed(r); err != nil {
			return SubjectSet{}, err
		}
	}

	var set SubjectSet
	if want.relation == "" {
		set.All = results[len(results)-1].Allowed
		candidates, results = candidates[:len(candidates)-1], results[:len(results)-1]
	}
	for i, r := range results {
		switch {
		case set.All && !r.Allowed:
			set.Except = append(set.Except, candidates[i])
		case !set.All && r.Allowed:
			set.Subjects = append(set.Subjects, candidates[i])
		}
	}
	return set, nil
}

// forEachEdge calls subject for every subject that a tuple read for rewrite
// r of n names, and push for every relation r reaches, including the
// subtracted side of exclusions.
func (q *request) forEachEdge(n objRel, r Rewrite, subject func(Subject), push func(objRel)) error {
	switch r := r.(type) {
	case direct:
		tuples, err := q.read(q.ctx, n.obj, n.rel)
		if err != nil {
			return err
		}
		for _, t := range tuples {
			subject(t.Subject)
			if t.Subject.Relation != "" {
				push(objRel{t.Subject.Object, t.Subject.Relation})
			}
		}
	case computed:
		push(objRel{n.obj, r.relation})
	case tupleToUserset:
		tuples, err := q.read(q.ctx, n.obj, r.tupleset)
		if err != nil {
			return err
		}
		for _, t := range tuples {
			if !t.Subject.isWildcard() {
				push(objRel{t.Subject.Object, r.computed})
			}
		}
	case union:
		return q.forEachChild(n, r.children, subject, push)
	case intersection:
		return q.forEachChild(n, r.children, subject, push)
	case exclusion:
		return q.forEachChild(n, []Rewrite{r.base, r.subtract}, subject, push)
	}
	return nil
}

func (q *request) forEachChild(n objRel, children []Rewrite, subject func(Subject), push func(objRel)) error {
	for _, c := range children {
		if err := q.forEachEdge(n, c, subject, push); err != nil {
			return err
		}
	}
	return nil
}

func unnamedID(named map[Subject]bool) string {
	ids := map[string]bool{}
	for s := range named {
		ids[s.Object.ID] = true
	}
	for i := 0; ; i++ {
		if id := "unnamed" + strconv.Itoa(i); !ids[id] {
			return id
		}
	}
}
