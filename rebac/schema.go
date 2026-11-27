package rebac

import (
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
)

// Rewrite defines how a relation is computed. Build one with Direct,
// Computed, TupleToUserset, Union, Intersection or Exclusion.
type Rewrite interface {
	isRewrite()
}

type direct struct{ allowed []string }
type computed struct{ relation string }
type tupleToUserset struct{ tupleset, computed string }
type union struct{ children []Rewrite }
type intersection struct{ children []Rewrite }
type exclusion struct{ base, subtract Rewrite }

func (direct) isRewrite()         {}
func (computed) isRewrite()       {}
func (tupleToUserset) isRewrite() {}
func (union) isRewrite()          {}
func (intersection) isRewrite()   {}
func (exclusion) isRewrite()      {}

// Direct grants the relation to subjects named in tuples for this relation.
// allowed lists the subject types that may be written, each one of
// "type" (an object, such as user), "type#relation" (a userset, such as
// group#member) or "type:*" (a wildcard, such as user:*), optionally
// followed by " with " and the name of a caveat that such tuples must
// carry, as in "user with office". A type without " with " allows only
// tuples without a caveat.
//
// A relation whose rewrite contains Direct can be written to; one without is
// a computed permission.
func Direct(allowed ...string) Rewrite { return direct{allowed: allowed} }

// Computed grants the relation to everyone who has another relation on the
// same object, for example viewer includes editor.
func Computed(relation string) Rewrite { return computed{relation: relation} }

// TupleToUserset follows the objects named by the tupleset relation and
// grants the relation to everyone who has the computed relation on them,
// for example "viewers of a doc include viewers of its parent folder" is
// TupleToUserset("parent", "viewer").
func TupleToUserset(tupleset, computed string) Rewrite {
	return tupleToUserset{tupleset: tupleset, computed: computed}
}

// Union grants the relation if any child grants it.
func Union(children ...Rewrite) Rewrite { return union{children: children} }

// Intersection grants the relation if all children grant it.
func Intersection(children ...Rewrite) Rewrite { return intersection{children: children} }

// Exclusion grants the relation if base grants it and subtract does not.
func Exclusion(base, subtract Rewrite) Rewrite { return exclusion{base: base, subtract: subtract} }

// TypeDef defines an object type. Build one with Type.
type TypeDef struct {
	name      string
	relations []RelationDef
}

// RelationDef defines a relation. Build one with Relation.
type RelationDef struct {
	name    string
	rewrite Rewrite
}

// Type defines an object type and its relations.
func Type(name string, relations ...RelationDef) TypeDef {
	return TypeDef{name: name, relations: relations}
}

// Relation defines a relation computed by rewrite.
func Relation(name string, rewrite Rewrite) RelationDef {
	return RelationDef{name: name, rewrite: rewrite}
}

// ErrInvalidSchema is returned by NewSchema.
var ErrInvalidSchema = errors.New("rebac: invalid schema")

type allowedSubject struct {
	typ      string
	relation string // userset relation, or empty
	wildcard bool
	caveat   string
}

func (a allowedSubject) matches(s Subject, caveat string) bool {
	if a.typ != s.Object.Type || a.caveat != caveat {
		return false
	}
	if a.wildcard {
		return s.isWildcard() && s.Relation == ""
	}
	return !s.isWildcard() && a.relation == s.Relation
}

func (a allowedSubject) String() string {
	switch {
	case a.wildcard:
		return a.typ + ":*" + a.withCaveat()
	case a.relation != "":
		return a.typ + "#" + a.relation + a.withCaveat()
	}
	return a.typ + a.withCaveat()
}

func (a allowedSubject) withCaveat() string {
	if a.caveat == "" {
		return ""
	}
	return " with " + a.caveat
}

type relationInfo struct {
	rewrite Rewrite
	allowed []allowedSubject // subjects that may be written; empty if not writable
}

func (info *relationInfo) admits(t Tuple) bool {
	for _, a := range info.allowed {
		if a.matches(t.Subject, t.Caveat.Name) {
			return true
		}
	}
	return false
}

// Definition is a type or caveat definition for NewSchema. Build one with
// Type or Caveat.
type Definition interface{ definition() }

func (TypeDef) definition()   {}
func (CaveatDef) definition() {}

// relationError is an ErrInvalidSchema about one relation.
type relationError struct{ typ, rel, msg string }

func (e *relationError) Error() string {
	return ErrInvalidSchema.Error() + ": " + e.typ + "#" + e.rel + ": " + e.msg
}

func (e *relationError) Unwrap() error { return ErrInvalidSchema }

// Schema is a validated set of type and caveat definitions. It is
// immutable.
type Schema struct {
	defs    []Definition
	caveats map[string]*CaveatDef
	types   map[string]map[string]*relationInfo
	reverse map[typeRel][]reverseEdge
}

// maxRewriteDepth bounds how deeply Union, Intersection and Exclusion nest,
// so that validating and evaluating a rewrite stays cheap and shallow.
const maxRewriteDepth = 64

// keywords are the words of the text form, which cannot be names.
var keywords = map[string]bool{"type": true, "relation": true, "caveat": true, "or": true, "and": true, "but": true, "not": true, "from": true, "with": true}

// validDefName reports whether s can name a type, relation, caveat or
// caveat parameter.
func validDefName(s string) bool { return validName(s) && !keywords[s] }

// NewSchema validates the definitions and returns a Schema. Names cannot be
// the keywords of the text form (see ParseSchema), and Union, Intersection
// and Exclusion nest at most 64 deep.
func NewSchema(defs ...Definition) (*Schema, error) {
	s := &Schema{defs: slices.Clone(defs), types: map[string]map[string]*relationInfo{}, caveats: map[string]*CaveatDef{}}
	var types []TypeDef
	for _, d := range defs {
		switch d := d.(type) {
		case TypeDef:
			types = append(types, d)
		case CaveatDef:
			if err := d.validate(); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidSchema, err)
			}
			if _, dup := s.caveats[d.name]; dup {
				return nil, fmt.Errorf("%w: duplicate caveat %q", ErrInvalidSchema, d.name)
			}
			s.caveats[d.name] = &d
		default:
			return nil, fmt.Errorf("%w: unknown definition %T", ErrInvalidSchema, d)
		}
	}
	for _, t := range types {
		if !validDefName(t.name) {
			return nil, fmt.Errorf("%w: type name %q", ErrInvalidSchema, t.name)
		}
		if _, dup := s.types[t.name]; dup {
			return nil, fmt.Errorf("%w: duplicate type %q", ErrInvalidSchema, t.name)
		}
		rels := map[string]*relationInfo{}
		for _, r := range t.relations {
			if !validDefName(r.name) {
				return nil, fmt.Errorf("%w: %s: relation name %q", ErrInvalidSchema, t.name, r.name)
			}
			if _, dup := rels[r.name]; dup {
				return nil, fmt.Errorf("%w: %s: duplicate relation %q", ErrInvalidSchema, t.name, r.name)
			}
			if r.rewrite == nil {
				return nil, fmt.Errorf("%w: %s#%s: nil rewrite", ErrInvalidSchema, t.name, r.name)
			}
			rels[r.name] = &relationInfo{rewrite: r.rewrite}
		}
		s.types[t.name] = rels
	}

	// Validate rewrites once every type and relation is known.
	for typ, name := range s.relationsInOrder() {
		info := s.types[typ][name]
		allowed, err := s.validateRewrite(typ, info.rewrite, 0)
		if err != nil {
			return nil, &relationError{typ, name, err.Error()}
		}
		info.allowed = allowed
	}
	if err := s.checkComputedCycles(); err != nil {
		return nil, err
	}
	s.reverse = s.reverseEdges()
	return s, nil
}

// relationsInOrder yields every type and relation in definition order, so
// that validation reports the first error deterministically.
func (s *Schema) relationsInOrder() iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for _, d := range s.defs {
			if t, ok := d.(TypeDef); ok {
				for _, r := range t.relations {
					if !yield(t.name, r.name) {
						return
					}
				}
			}
		}
	}
}

func (s *Schema) relation(typ, rel string) (*relationInfo, bool) {
	info, ok := s.types[typ][rel]
	return info, ok
}

func (s *Schema) hasType(typ string) bool {
	_, ok := s.types[typ]
	return ok
}

// validateRewrite checks references in r and returns the subjects that
// Direct nodes in r allow. depth is the number of operators above r.
func (s *Schema) validateRewrite(typ string, r Rewrite, depth int) ([]allowedSubject, error) {
	switch r := r.(type) {
	case direct:
		if len(r.allowed) == 0 {
			return nil, errors.New("Direct needs at least one allowed subject type")
		}
		var out []allowedSubject
		for _, spec := range r.allowed {
			a, err := s.parseAllowed(spec)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		}
		return out, nil
	case computed:
		if _, ok := s.relation(typ, r.relation); !ok {
			return nil, fmt.Errorf("Computed: unknown relation %q", clip(r.relation))
		}
		return nil, nil
	case tupleToUserset:
		ts, ok := s.relation(typ, r.tupleset)
		if !ok {
			return nil, fmt.Errorf("TupleToUserset: unknown tupleset relation %q", clip(r.tupleset))
		}
		d, ok := ts.rewrite.(direct)
		if !ok {
			return nil, fmt.Errorf("TupleToUserset: tupleset relation %q must be a plain Direct relation", clip(r.tupleset))
		}
		found := false
		for _, spec := range d.allowed {
			a, err := s.parseAllowed(spec)
			if err != nil {
				return nil, err
			}
			if a.wildcard || a.relation != "" {
				return nil, fmt.Errorf("TupleToUserset: tupleset relation %q may only allow plain object types, not %q", clip(r.tupleset), clip(spec))
			}
			if _, ok := s.relation(a.typ, r.computed); ok {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("TupleToUserset: no type allowed by %q has relation %q", clip(r.tupleset), clip(r.computed))
		}
		return nil, nil
	case union:
		return s.validateChildren(typ, r.children, "Union", depth)
	case intersection:
		return s.validateChildren(typ, r.children, "Intersection", depth)
	case exclusion:
		if r.base == nil || r.subtract == nil {
			return nil, errors.New("Exclusion: nil operand")
		}
		return s.validateChildren(typ, []Rewrite{r.base, r.subtract}, "Exclusion", depth)
	default:
		return nil, fmt.Errorf("unknown rewrite %T", r)
	}
}

func (s *Schema) validateChildren(typ string, children []Rewrite, op string, depth int) ([]allowedSubject, error) {
	if depth == maxRewriteDepth {
		return nil, fmt.Errorf("operators nest more than %d deep", maxRewriteDepth)
	}
	if len(children) == 0 {
		return nil, fmt.Errorf("%s needs at least one operand", op)
	}
	var out []allowedSubject
	for _, c := range children {
		if c == nil {
			return nil, fmt.Errorf("%s: nil operand", op)
		}
		a, err := s.validateRewrite(typ, c, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, a...)
	}
	return out, nil
}

func (s *Schema) parseAllowed(spec string) (allowedSubject, error) {
	base, caveat, withCaveat := strings.Cut(spec, " with ")
	if _, ok := s.caveats[caveat]; withCaveat && !ok {
		return allowedSubject{}, fmt.Errorf("allowed subject %q: unknown caveat %q", clip(spec), clip(caveat))
	}
	a, err := s.parseSubjectType(base)
	a.caveat = caveat
	return a, err
}

func (s *Schema) parseSubjectType(spec string) (allowedSubject, error) {
	var a allowedSubject
	switch {
	case strings.HasSuffix(spec, ":*"):
		a = allowedSubject{typ: strings.TrimSuffix(spec, ":*"), wildcard: true}
	case strings.Contains(spec, "#"):
		typ, rel, _ := strings.Cut(spec, "#")
		a = allowedSubject{typ: typ, relation: rel}
		if _, ok := s.relation(typ, rel); !ok {
			return a, fmt.Errorf("allowed subject %q: unknown relation", clip(spec))
		}
	default:
		a = allowedSubject{typ: spec}
	}
	if !s.hasType(a.typ) {
		return a, fmt.Errorf("allowed subject %q: unknown type", clip(spec))
	}
	return a, nil
}

// checkComputedCycles rejects relations that depend on themselves through
// Computed alone (for example a = b, b = a). Such definitions can never be
// satisfied and indicate a mistake. Cycles through tuples (nested groups)
// are legitimate and handled at check time.
func (s *Schema) checkComputedCycles() error {
	type node struct{ typ, rel string }
	const (
		unvisited = iota
		visiting
		done
	)
	state := map[node]int{}
	var visit func(n node) error
	visit = func(n node) error {
		switch state[n] {
		case visiting:
			return &relationError{n.typ, n.rel, "depends on itself through Computed"}
		case done:
			return nil
		}
		state[n] = visiting
		for _, dep := range computedRefs(s.types[n.typ][n.rel].rewrite) {
			if err := visit(node{n.typ, dep}); err != nil {
				return err
			}
		}
		state[n] = done
		return nil
	}
	for typ, rel := range s.relationsInOrder() {
		if err := visit(node{typ, rel}); err != nil {
			return err
		}
	}
	return nil
}

func computedRefs(r Rewrite) []string {
	switch r := r.(type) {
	case computed:
		return []string{r.relation}
	case union:
		return flatRefs(r.children)
	case intersection:
		return flatRefs(r.children)
	case exclusion:
		return flatRefs([]Rewrite{r.base, r.subtract})
	}
	return nil
}

func flatRefs(rs []Rewrite) []string {
	var out []string
	for _, r := range rs {
		out = append(out, computedRefs(r)...)
	}
	return out
}
