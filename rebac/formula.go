package rebac

import (
	"cmp"
	"errors"
	"math"
	"slices"
	"strings"
)

// ErrExclusionCycle is returned when a check depends on its own result
// through the subtracted side of an Exclusion and nothing else decides it,
// as in "viewers are the users who are not viewers". Such data defines no
// answer, so the check fails closed.
var ErrExclusionCycle = errors.New("rebac: relation depends on itself through an exclusion")

// formula is the value of a rewrite for one subject, as far as it is known.
// A decided formula is true, false or unknown (an error stopped the
// evaluation). Any other formula refers to atoms (object#relation pairs)
// that are still being evaluated further up the current path.
type formula struct {
	op   formulaOp
	why  error      // opUnknown
	ref  objRel     // opRef
	args []*formula // opNot: one; opAnd, opOr: two or more
}

type formulaOp uint8

const (
	opFalse formulaOp = iota
	opTrue
	opUnknown
	opRef
	opNot
	opAnd
	opOr
)

var (
	fFalse = &formula{op: opFalse}
	fTrue  = &formula{op: opTrue}
)

func (f *formula) decided() bool { return f.op <= opUnknown }

// result is a formula with the equations of the undecided atoms below it.
// minDepth is the smallest path depth of an atom it refers to; noDepth if
// it is decided.
type result struct {
	f        *formula
	minDepth int
	eqs      map[objRel]*formula
}

const noDepth = math.MaxInt

func decided(f *formula) result { return result{f: f, minDepth: noDepth} }

var (
	resFalse = decided(fFalse)
	resTrue  = decided(fTrue)
)

func resUnknown(why error) result { return decided(&formula{op: opUnknown, why: why}) }

func resBool(b bool) result {
	if b {
		return resTrue
	}
	return resFalse
}

// join combines results with opAnd or opOr in three-valued logic: the value
// that decides op (false for opAnd, true for opOr) wins over unknown values
// and references.
func join(op formulaOp, rs []result) result {
	wins, neutral := opTrue, opFalse
	if op == opAnd {
		wins, neutral = opFalse, opTrue
	}
	var args []*formula
	minDepth := noDepth
	var eqs map[objRel]*formula
	allUnknown := true
	for _, r := range rs {
		switch r.f.op {
		case wins:
			return r
		case neutral:
			continue
		}
		args = append(args, r.f)
		allUnknown = allUnknown && r.f.op == opUnknown
		minDepth = min(minDepth, r.minDepth)
		eqs = mergeEqs(eqs, r.eqs)
	}
	switch {
	case len(args) == 0:
		return resBool(neutral == opTrue)
	case allUnknown:
		why := args[0].why
		for _, a := range args[1:] {
			why = mergeWhy(why, a.why)
		}
		return resUnknown(why)
	case len(args) == 1:
		return result{f: args[0], minDepth: minDepth, eqs: eqs}
	}
	return result{f: &formula{op: op, args: args}, minDepth: minDepth, eqs: eqs}
}

func negate(r result) result {
	switch r.f.op {
	case opTrue:
		return resFalse
	case opFalse:
		return resTrue
	case opUnknown:
		return r
	}
	return result{f: &formula{op: opNot, args: []*formula{r.f}}, minDepth: r.minDepth, eqs: r.eqs}
}

// mergeEqs adds the equations of src to dst. Two equations for the same
// atom come from evaluating it on different paths. Either may be kept: they
// can differ only in unknowns from limits, which never decide a value.
func mergeEqs(dst, src map[objRel]*formula) map[objRel]*formula {
	if dst == nil {
		return src
	}
	for k, v := range src {
		if _, ok := dst[k]; !ok {
			dst[k] = v
		}
	}
	return dst
}

// mergeWhy picks the error to report for an unknown value that has two
// causes. An error from the store or a limit is reported first, because no
// input from the caller can fix it, then missing caveat context, merging
// the missing parameters, then a cycle. Between other equals the first
// one wins.
func mergeWhy(a, b error) error {
	switch ra, rb := whyRank(a), whyRank(b); {
	case rb > ra:
		return b
	case ra == rb && ra == rankMissing:
		var ma, mb *MissingContextError
		errors.As(a, &ma)
		errors.As(b, &mb)
		params := append(slices.Clone(ma.Params), mb.Params...)
		slices.Sort(params)
		return &MissingContextError{Params: slices.Compact(params)}
	}
	return a
}

const (
	rankCycle = iota
	rankMissing
	rankError
)

func whyRank(err error) int {
	var missing *MissingContextError
	switch {
	case err == nil:
		return rankCycle - 1
	case errors.Is(err, ErrExclusionCycle):
		return rankCycle
	case errors.As(err, &missing):
		return rankMissing
	}
	return rankError
}

// solve returns the value of every atom defined by eqs in the well-founded
// model of the equations (Van Gelder, Ross and Schlipf, 1991), computed with
// the alternating fixpoint. Every atom that eqs refers to must be defined in
// eqs. An unknown constant acts as an atom that is neither true nor false.
// An undefined atom is unknown with the cause that causes picks.
func solve(eqs map[objRel]*formula) map[objRel]*formula {
	s := &system{index: map[objRel]int{}}
	keys := make([]objRel, 0, len(eqs))
	for k := range eqs {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, compareObjRel)
	for i, k := range keys {
		s.index[k] = i
	}
	s.eqs = make([]cnode, len(keys))
	for i, k := range keys {
		// compile may append to s.eqs, so assign through a temporary.
		e := s.compile(eqs[k])
		s.eqs[i] = e
	}

	n := len(s.eqs)
	under := make([]bool, n)
	var over []bool
	for {
		over = s.least(under, true)
		next := s.least(over, false)
		if slices.Equal(next, under) {
			break
		}
		under = next
	}

	vals := make([]tv, n)
	for i := range n {
		switch {
		case under[i]:
			vals[i] = tvTrue
		case !over[i]:
			vals[i] = tvFalse
		default:
			vals[i] = tvUnknown
		}
	}
	why := s.causes(vals)

	out := make(map[objRel]*formula, len(keys))
	for i, k := range keys {
		switch vals[i] {
		case tvTrue:
			out[k] = fTrue
		case tvFalse:
			out[k] = fFalse
		default:
			out[k] = &formula{op: opUnknown, why: why[i]}
		}
	}
	return out
}

// causes returns why each undefined atom is undefined: the highest ranked
// error it depends on, or ErrExclusionCycle if it only depends on itself.
func (s *system) causes(vals []tv) []error {
	why := make([]error, len(vals))
	for i, v := range vals {
		if v == tvUnknown {
			why[i] = ErrExclusionCycle
		}
	}
	for changed := true; changed; {
		changed = false
		for i, v := range vals {
			if v != tvUnknown {
				continue
			}
			if _, w := s.kleene(s.eqs[i], vals, why); whyRank(w) > whyRank(why[i]) {
				why[i] = w
				changed = true
			}
		}
	}
	return why
}

func compareObjRel(a, b objRel) int {
	return cmp.Or(strings.Compare(a.obj.Type, b.obj.Type), strings.Compare(a.obj.ID, b.obj.ID), strings.Compare(a.rel, b.rel))
}

// system is a set of equations over numbered atoms in which negation only
// applies to atoms: compile gives every negated subformula an atom of its
// own.
type system struct {
	index map[objRel]int
	eqs   []cnode
}

type cnode struct {
	op   formulaOp
	why  error
	at   int // opRef, opNot
	args []cnode
}

type tv uint8

const (
	tvFalse tv = iota
	tvTrue
	tvUnknown
)

func (s *system) compile(f *formula) cnode {
	switch f.op {
	case opRef:
		return cnode{op: opRef, at: s.index[f.ref]}
	case opNot:
		if f.args[0].op == opRef {
			return cnode{op: opNot, at: s.index[f.args[0].ref]}
		}
		aux := len(s.eqs)
		s.eqs = append(s.eqs, cnode{})
		e := s.compile(f.args[0])
		s.eqs[aux] = e
		return cnode{op: opNot, at: aux}
	case opAnd, opOr:
		args := make([]cnode, len(f.args))
		for i, a := range f.args {
			args[i] = s.compile(a)
		}
		return cnode{op: f.op, args: args}
	}
	return cnode{op: f.op, why: f.why}
}

// least returns the least model of the equations when every negated atom
// is read from neg and every unknown constant is unknownTrue.
func (s *system) least(neg []bool, unknownTrue bool) []bool {
	v := make([]bool, len(s.eqs))
	for changed := true; changed; {
		changed = false
		for i, e := range s.eqs {
			if !v[i] && s.holds(e, v, neg, unknownTrue) {
				v[i] = true
				changed = true
			}
		}
	}
	return v
}

func (s *system) holds(e cnode, v, neg []bool, unknownTrue bool) bool {
	switch e.op {
	case opTrue:
		return true
	case opUnknown:
		return unknownTrue
	case opRef:
		return v[e.at]
	case opNot:
		return !neg[e.at]
	case opAnd:
		for _, a := range e.args {
			if !s.holds(a, v, neg, unknownTrue) {
				return false
			}
		}
		return true
	case opOr:
		for _, a := range e.args {
			if s.holds(a, v, neg, unknownTrue) {
				return true
			}
		}
	}
	return false
}

// kleene evaluates e in three-valued logic over vals and returns its value
// and, if it is unknown, why.
func (s *system) kleene(e cnode, vals []tv, why []error) (tv, error) {
	switch e.op {
	case opTrue:
		return tvTrue, nil
	case opFalse:
		return tvFalse, nil
	case opUnknown:
		return tvUnknown, e.why
	case opRef:
		return vals[e.at], why[e.at]
	case opNot:
		switch vals[e.at] {
		case tvTrue:
			return tvFalse, nil
		case tvFalse:
			return tvTrue, nil
		}
		return tvUnknown, why[e.at]
	}
	wins := tvTrue
	if e.op == opAnd {
		wins = tvFalse
	}
	out, w := tvFalse+tvTrue-wins, error(nil)
	for _, a := range e.args {
		v, aw := s.kleene(a, vals, why)
		switch {
		case v == wins:
			return wins, nil
		case v == tvUnknown:
			if out == tvUnknown {
				w = mergeWhy(w, aw)
			} else {
				out, w = tvUnknown, aw
			}
		}
	}
	return out, w
}
