package rebac

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// TreeOp is the kind of a UsersetTree node.
type TreeOp int

const (
	// TreeLeaf is a single member: an object such as user:alice, a wildcard
	// such as user:*, or a userset such as group:eng#member, which Expand
	// does not follow.
	TreeLeaf TreeOp = iota
	// TreeUnion has the members of any child. With no children it is empty.
	TreeUnion
	// TreeIntersection has the members of all children.
	TreeIntersection
	// TreeExclusion has the members of Children[0] that are not members
	// of Children[1].
	TreeExclusion
)

// UsersetTree is a node of the tree that Expand returns.
type UsersetTree struct {
	Op TreeOp
	// Userset is the object#relation whose members this node computes. It
	// is zero for a node that computes part of a rewrite.
	Userset Subject
	// Subject is the member of a TreeLeaf node.
	Subject  Subject
	Children []*UsersetTree
	// Caveat, if set, makes the node conditional: it comes from a tuple
	// with a caveat, either the leaf's own or, for a node reached through
	// TupleToUserset, the tuple naming its object.
	Caveat TupleCaveat
}

// Expand returns the userset tree of object#relation: how the schema's
// rewrites compute its members. Computed and TupleToUserset rewrites are
// followed to the relations they name; Direct rewrites end in a leaf per
// tuple subject. Usersets named by tuples, such as group:eng#member, are
// leaves; expand them with another call.
//
// A relation reached again on the same path, through a cycle in the data,
// is a leaf naming the userset itself. Expand is bounded by the same depth
// and evaluation limits as Check, and fails with ErrTooComplex beyond them.
// It reads one revision of the store, like Check.
func (e *Engine) Expand(ctx context.Context, object Object, relation string, opts ...QueryOption) (*UsersetTree, error) {
	if err := validateObject(object, false); err != nil {
		return nil, err
	}
	if _, ok := e.schema.relation(object.Type, relation); !ok {
		return nil, fmt.Errorf("%w: %s#%s", ErrUnknownRelation, object.Type, relation)
	}
	x := &expander{request: e.newRequest(ctx, opts)}
	if _, err := x.revision(); err != nil {
		return nil, err
	}
	return x.relation(nil, object, relation)
}

type expander struct {
	*request
	evals int
}

func (x *expander) relation(parent *path, obj Object, rel string) (*UsersetTree, error) {
	depth := parent.next()
	if depth > x.e.maxDepth {
		return nil, fmt.Errorf("%w: depth exceeds %d", ErrTooComplex, x.e.maxDepth)
	}
	if x.evals++; x.evals > x.e.maxEvaluations {
		return nil, fmt.Errorf("%w: more than %d evaluations", ErrTooComplex, x.e.maxEvaluations)
	}
	if err := x.ctx.Err(); err != nil {
		return nil, err
	}
	set := Userset(obj.Type, obj.ID, rel)
	a := objRel{obj, rel}
	if _, ok := parent.find(a); ok {
		return &UsersetTree{Op: TreeLeaf, Subject: set}, nil
	}
	info, _ := x.e.schema.relation(obj.Type, rel)
	t, err := x.rewrite(&path{at: a, parent: parent, depth: depth}, obj, rel, info.rewrite)
	if err != nil {
		return nil, err
	}
	if t.Userset != (Subject{}) {
		t = &UsersetTree{Op: TreeUnion, Children: []*UsersetTree{t}}
	}
	t.Userset = set
	return t, nil
}

func (x *expander) rewrite(p *path, obj Object, rel string, rw Rewrite) (*UsersetTree, error) {
	switch rw := rw.(type) {
	case direct:
		tuples, err := x.read(x.ctx, obj, rel)
		if err != nil {
			return nil, err
		}
		t := &UsersetTree{Op: TreeUnion}
		for _, tp := range sortedTuples(tuples) {
			t.Children = append(t.Children, &UsersetTree{Op: TreeLeaf, Subject: tp.Subject, Caveat: tp.Caveat})
		}
		return t, nil
	case computed:
		return x.relation(p, obj, rw.relation)
	case tupleToUserset:
		tuples, err := x.read(x.ctx, obj, rw.tupleset)
		if err != nil {
			return nil, err
		}
		t := &UsersetTree{Op: TreeUnion}
		for _, tp := range sortedTuples(tuples) {
			s := tp.Subject
			if _, ok := x.e.schema.relation(s.Object.Type, rw.computed); !ok {
				continue
			}
			child, err := x.relation(p, s.Object, rw.computed)
			if err != nil {
				return nil, err
			}
			child.Caveat = tp.Caveat
			t.Children = append(t.Children, child)
		}
		return t, nil
	case union:
		return x.operator(p, obj, rel, TreeUnion, rw.children)
	case intersection:
		return x.operator(p, obj, rel, TreeIntersection, rw.children)
	case exclusion:
		return x.operator(p, obj, rel, TreeExclusion, []Rewrite{rw.base, rw.subtract})
	}
	return nil, fmt.Errorf("rebac: unknown rewrite %T", rw)
}

func (x *expander) operator(p *path, obj Object, rel string, op TreeOp, children []Rewrite) (*UsersetTree, error) {
	t := &UsersetTree{Op: op}
	for _, c := range children {
		child, err := x.rewrite(p, obj, rel, c)
		if err != nil {
			return nil, err
		}
		t.Children = append(t.Children, child)
	}
	return t, nil
}

func sortedTuples(tuples []Tuple) []Tuple {
	out := slices.Clone(tuples)
	slices.SortFunc(out, func(a, b Tuple) int { return strings.Compare(a.String(), b.String()) })
	return out
}
