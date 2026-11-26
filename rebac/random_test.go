package rebac

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

type world struct {
	schema  *Schema
	tuples  []Tuple
	objects []Object
	users   []Subject
}

var (
	worldTypes     = []string{"a", "b", "c"}
	worldRelations = []string{"p", "r0", "r1", "r2", "r3"}
)

// randomWorld returns a schema over the object types a, b and c, which all
// have the relations p (a tupleset), r0 (directly writable) and r1 to r3
// (random rewrites), and tuples over three objects per type and three
// users. Usersets of any relation may be written, so the data has cycles,
// including cycles through the subtracted side of exclusions.
func randomWorld(t testing.TB, rng *rand.Rand) world {
	t.Helper()
	specs := []string{"user", "user:*"}
	for _, typ := range worldTypes {
		for _, r := range worldRelations[1:] {
			specs = append(specs, typ+"#"+r)
		}
	}
	pick := func(from []string) []string {
		var out []string
		for _, s := range from {
			if rng.IntN(3) == 0 {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			out = append(out, from[rng.IntN(len(from))])
		}
		return out
	}
	other := func() string { return worldRelations[1+rng.IntN(len(worldRelations)-1)] }
	var gen func(depth int) Rewrite
	gen = func(depth int) Rewrite {
		k := rng.IntN(10)
		if depth >= 2 {
			k = rng.IntN(6)
		}
		switch {
		case k < 2:
			return Direct(pick(specs)...)
		case k < 4:
			return Computed(other())
		case k < 6:
			return TupleToUserset("p", other())
		case k < 7:
			return Union(gen(depth+1), gen(depth+1))
		case k < 8:
			return Intersection(gen(depth+1), gen(depth+1))
		}
		return Exclusion(gen(depth+1), gen(depth+1))
	}

	var w world
	for {
		defs := []TypeDef{Type("user")}
		for _, typ := range worldTypes {
			defs = append(defs, Type(typ,
				Relation("p", Direct(pick(worldTypes)...)),
				Relation("r0", Direct(pick(specs)...)),
				Relation("r1", gen(0)),
				Relation("r2", gen(0)),
				Relation("r3", gen(0)),
			))
		}
		s, err := NewSchema(defs...)
		if err == nil {
			w.schema = s
			break
		}
	}

	for i := range 3 {
		w.users = append(w.users, Sub("user", fmt.Sprintf("u%d", i)))
		for _, typ := range worldTypes {
			w.objects = append(w.objects, Obj(typ, fmt.Sprintf("%s%d", typ, i)))
		}
	}
	for _, o := range w.objects {
		for _, r := range worldRelations {
			info, _ := w.schema.relation(o.Type, r)
			for range rng.IntN(3) {
				if len(info.allowed) == 0 {
					break
				}
				a := info.allowed[rng.IntN(len(info.allowed))]
				var s Subject
				switch {
				case a.wildcard:
					s = AllOf(a.typ)
				case a.typ == "user":
					s = Sub("user", fmt.Sprintf("u%d", rng.IntN(3)))
				default:
					s = Subject{Object: Obj(a.typ, fmt.Sprintf("%s%d", a.typ, rng.IntN(3))), Relation: a.relation}
				}
				w.tuples = append(w.tuples, Tuple{Object: o, Relation: r, Subject: s})
			}
		}
	}
	return w
}

func (w world) subjects() []Subject {
	out := append(slices.Clone(w.users), Sub("user", "fresh"))
	for _, o := range w.objects[:3] {
		out = append(out, Userset(o.Type, o.ID, "r1"))
	}
	return out
}

func (w world) engine(t testing.TB, opts ...Option) *Engine {
	t.Helper()
	e, err := NewEngine(w.schema, NewMemoryStore(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Write(context.Background(), w.tuples, nil); err != nil {
		t.Fatal(err)
	}
	return e
}

// wfs is a reference evaluator: it grounds the schema and tuples into a
// normal logic program for one subject, with an atom per relation and per
// rewrite node of every object, and computes its well-founded model with
// the alternating fixpoint, as defined by Van Gelder, Ross and Schlipf.
type wfs struct {
	w       world
	subject Subject
	byKey   map[objRel][]Tuple
	ids     map[string]int
	rules   []wfsRule
}

type wfsRule struct {
	head int
	body []wfsLit
}

type wfsLit struct {
	at  int
	neg bool
}

func newWFS(w world, subject Subject) *wfs {
	g := &wfs{w: w, subject: subject, byKey: map[objRel][]Tuple{}, ids: map[string]int{}}
	for _, t := range w.tuples {
		k := objRel{t.Object, t.Relation}
		g.byKey[k] = append(g.byKey[k], t)
	}
	return g
}

func (g *wfs) atom(key string) (int, bool) {
	if id, ok := g.ids[key]; ok {
		return id, false
	}
	g.ids[key] = len(g.ids)
	return g.ids[key], true
}

func (g *wfs) rule(head int, body ...wfsLit) { g.rules = append(g.rules, wfsRule{head, body}) }

func (g *wfs) relation(o Object, r string) int {
	key := o.String() + "#" + r
	id, fresh := g.atom(key)
	if !fresh {
		return id
	}
	if g.subject == Userset(o.Type, o.ID, r) {
		g.rule(id)
	}
	if info, ok := g.w.schema.relation(o.Type, r); ok {
		g.rule(id, wfsLit{at: g.node(o, r, info.rewrite, key+"/")})
	}
	return id
}

func (g *wfs) node(o Object, r string, rw Rewrite, key string) int {
	id, _ := g.atom(key)
	switch rw := rw.(type) {
	case direct:
		for _, t := range g.byKey[objRel{o, r}] {
			s := t.Subject
			switch {
			case s == g.subject:
				g.rule(id)
			case s.isWildcard():
				if g.subject.Relation == "" && g.subject.Object.Type == s.Object.Type {
					g.rule(id)
				}
			case s.Relation != "":
				g.rule(id, wfsLit{at: g.relation(s.Object, s.Relation)})
			}
		}
	case computed:
		g.rule(id, wfsLit{at: g.relation(o, rw.relation)})
	case tupleToUserset:
		for _, t := range g.byKey[objRel{o, rw.tupleset}] {
			g.rule(id, wfsLit{at: g.relation(t.Subject.Object, rw.computed)})
		}
	case union:
		for i, c := range rw.children {
			g.rule(id, wfsLit{at: g.node(o, r, c, fmt.Sprintf("%s%d/", key, i))})
		}
	case intersection:
		var body []wfsLit
		for i, c := range rw.children {
			body = append(body, wfsLit{at: g.node(o, r, c, fmt.Sprintf("%s%d/", key, i))})
		}
		g.rule(id, body...)
	case exclusion:
		g.rule(id,
			wfsLit{at: g.node(o, r, rw.base, key+"b/")},
			wfsLit{at: g.node(o, r, rw.subtract, key+"s/"), neg: true})
	}
	return id
}

// gamma returns the least model of the program after removing every rule
// with a negative literal on an atom in j and every remaining negative
// literal.
func (g *wfs) gamma(j []bool) []bool {
	m := make([]bool, len(g.ids))
	for changed := true; changed; {
		changed = false
	rules:
		for _, r := range g.rules {
			if m[r.head] {
				continue
			}
			for _, l := range r.body {
				if l.neg && j[l.at] || !l.neg && !m[l.at] {
					continue rules
				}
			}
			m[r.head] = true
			changed = true
		}
	}
	return m
}

type wfsValue int

const (
	wfsFalse wfsValue = iota
	wfsTrue
	wfsUndefined
)

// value returns the value of subject's relation r on o.
func (g *wfs) value(o Object, r string) wfsValue {
	id := g.relation(o, r)
	under := make([]bool, len(g.ids))
	var over []bool
	for {
		over = g.gamma(under)
		next := g.gamma(over)
		if slices.Equal(next, under) {
			break
		}
		under = next
	}
	switch {
	case under[id]:
		return wfsTrue
	case !over[id]:
		return wfsFalse
	}
	return wfsUndefined
}

func TestCheckMatchesWellFoundedSemantics(t *testing.T) {
	seeds := 200
	if testing.Short() {
		seeds = 40
	}
	counts := map[wfsValue]int{}
	for seed := range seeds {
		rng := rand.New(rand.NewPCG(uint64(seed), 1))
		w := randomWorld(t, rng)
		engines := map[string]*Engine{
			"sequential": w.engine(t, WithMaxDepth(1000), WithMaxEvaluations(1<<24)),
			"parallel":   w.engine(t, WithMaxDepth(1000), WithMaxEvaluations(1<<24), WithConcurrency(4)),
		}
		for _, sub := range w.subjects() {
			for _, o := range w.objects {
				for _, r := range worldRelations {
					want := newWFS(w, sub).value(o, r)
					counts[want]++
					for name, e := range engines {
						ok, err := e.Check(context.Background(), o, r, sub)
						var got wfsValue
						switch {
						case ok && err == nil:
							got = wfsTrue
						case !ok && err == nil:
							got = wfsFalse
						case !ok && err == ErrExclusionCycle:
							got = wfsUndefined
						default:
							t.Fatalf("seed %d %s: Check(%s#%s@%s) = %v, %v", seed, name, o, r, sub, ok, err)
						}
						if got != want {
							t.Fatalf("seed %d %s: Check(%s#%s@%s) = %v, %v; well-founded value %v", seed, name, o, r, sub, ok, err, want)
						}
					}
				}
			}
		}
	}
	if counts[wfsTrue] == 0 || counts[wfsFalse] == 0 || counts[wfsUndefined] == 0 {
		t.Fatalf("generator does not cover every value: %v", counts)
	}
	t.Logf("checked values: %v", counts)
}
