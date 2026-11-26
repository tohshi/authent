package rebac

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func render(t *UsersetTree) string {
	var s string
	switch t.Op {
	case TreeLeaf:
		s = t.Subject.String()
	default:
		sep := map[TreeOp]string{TreeUnion: " | ", TreeIntersection: " & ", TreeExclusion: " - "}[t.Op]
		var parts []string
		for _, c := range t.Children {
			parts = append(parts, render(c))
		}
		s = "(" + strings.Join(parts, sep) + ")"
	}
	if t.Userset != (Subject{}) {
		s = t.Userset.String() + "=" + s
	}
	return s
}

func TestExpand(t *testing.T) {
	e := newEngine(t,
		"group:eng#member@user:alice",
		"group:eng#member@group:backend#member",
		"folder:root#owner@user:carol",
		"folder:root#viewer@user:*",
		"folder:projects#parent@folder:root",
		"folder:projects#viewer@group:eng#member",
		"doc:design#parent@folder:projects",
		"doc:design#owner@user:dave",
		"doc:design#viewer@user:erin",
		"doc:design#banned@user:bob",
		"doc:design#cleared@user:alice",
	)
	for _, tc := range []struct{ object, relation, want string }{
		{"group:eng", "member", "group:eng#member=(group:backend#member | user:alice)"},
		{"group:none", "member", "group:none#member=()"},
		{"doc:design", "editor", "doc:design#editor=(() | doc:design#owner=(user:dave))"},
		{"folder:projects", "viewer", "folder:projects#viewer=((group:eng#member) | folder:projects#owner=() | (" +
			"folder:root#viewer=((user:*) | folder:root#owner=(user:carol) | ())))"},
		{"doc:design", "view_secret", "doc:design#view_secret=(" +
			"doc:design#viewer=(((user:erin) | doc:design#editor=(() | doc:design#owner=(user:dave)) | (" +
			"folder:projects#viewer=((group:eng#member) | folder:projects#owner=() | (" +
			"folder:root#viewer=((user:*) | folder:root#owner=(user:carol) | ()))))) - doc:design#banned=(user:bob))" +
			" & doc:design#cleared=(user:alice))"},
	} {
		obj, _ := ParseObject(tc.object)
		tree, err := e.Expand(context.Background(), obj, tc.relation)
		if err != nil {
			t.Fatalf("Expand(%s#%s): %v", tc.object, tc.relation, err)
		}
		if got := render(tree); got != tc.want {
			t.Errorf("Expand(%s#%s) =\n\t%s\nwant\n\t%s", tc.object, tc.relation, got, tc.want)
		}
	}
}

func TestExpandCycle(t *testing.T) {
	e := newEngine(t,
		"folder:a#parent@folder:b",
		"folder:b#parent@folder:a",
		"folder:b#viewer@user:bob",
	)
	tree, err := e.Expand(context.Background(), Obj("folder", "a"), "viewer")
	if err != nil {
		t.Fatal(err)
	}
	want := "folder:a#viewer=(() | folder:a#owner=() | (folder:b#viewer=((user:bob) | folder:b#owner=() | (folder:a#viewer))))"
	if got := render(tree); got != want {
		t.Errorf("Expand = %s\nwant %s", got, want)
	}
}

func TestExpandFailsClosed(t *testing.T) {
	ctx := context.Background()
	e, _ := NewEngine(driveSchema(t), NewMemoryStore(), WithMaxDepth(5))
	for i := range 9 {
		write(t, e, fmt.Sprintf("folder:f%d#parent@folder:f%d", i, i+1))
	}
	if _, err := e.Expand(ctx, Obj("folder", "f0"), "viewer"); !errors.Is(err, ErrTooComplex) {
		t.Errorf("deep Expand: %v, want ErrTooComplex", err)
	}
	if _, err := e.Expand(ctx, Obj("folder", "f6"), "viewer"); err != nil {
		t.Errorf("shallow Expand: %v", err)
	}

	e, _ = NewEngine(driveSchema(t), NewMemoryStore(), WithMaxEvaluations(10))
	for i := range 20 {
		write(t, e, fmt.Sprintf("doc:d#parent@folder:f%d", i))
	}
	if _, err := e.Expand(ctx, Obj("doc", "d"), "viewer"); !errors.Is(err, ErrTooComplex) {
		t.Errorf("wide Expand: %v, want ErrTooComplex", err)
	}

	e, _ = NewEngine(driveSchema(t), &failingStore{MemoryStore: NewMemoryStore(), failObject: Obj("doc", "d"), failRelation: "banned"})
	if _, err := e.Expand(ctx, Obj("doc", "d"), "viewer"); !errors.Is(err, errStore) {
		t.Errorf("Expand with failing store: %v, want errStore", err)
	}
	if _, err := e.Expand(ctx, Obj("doc", "d"), "nope"); !errors.Is(err, ErrUnknownRelation) {
		t.Errorf("unknown relation: %v", err)
	}
	if _, err := e.Expand(ctx, Obj("doc", "*"), "viewer"); !errors.Is(err, ErrInvalidTuple) {
		t.Errorf("wildcard object: %v", err)
	}
}
