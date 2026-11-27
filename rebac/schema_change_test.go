package rebac

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func schemaChangeEngines(t *testing.T) (old, narrowed *Engine) {
	t.Helper()
	common := []Definition{
		Type("user"),
		Type("group", Relation("member", Direct("user"))),
		Type("folder", Relation("viewer", Direct("user"))),
		Type("project", Relation("viewer", Direct("user"))),
	}
	oldSchema, err := NewSchema(append(common,
		Type("doc",
			Relation("parent", Direct("folder", "project")),
			Relation("viewer", Union(Direct("user", "group#member", "user:*"), TupleToUserset("parent", "viewer"))),
		))...)
	if err != nil {
		t.Fatal(err)
	}
	newSchema, err := NewSchema(append(common,
		Type("doc",
			Relation("parent", Direct("folder")),
			Relation("viewer", Union(Direct("user"), TupleToUserset("parent", "viewer"))),
		))...)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	if old, err = NewEngine(oldSchema, store); err != nil {
		t.Fatal(err)
	}
	if narrowed, err = NewEngine(newSchema, store); err != nil {
		t.Fatal(err)
	}
	write(t, old,
		"group:g#member@user:a",
		"project:p#viewer@user:a",
		"doc:1#viewer@group:g#member",
		"doc:2#viewer@user:*",
		"doc:3#parent@project:p",
		"doc:4#viewer@user:a",
	)
	return old, narrowed
}

func TestNarrowedSchemaRevokesStoredGrants(t *testing.T) {
	ctx := context.Background()
	old, e := schemaChangeEngines(t)
	a := Sub("user", "a")
	docs := []Object{Obj("doc", "1"), Obj("doc", "2"), Obj("doc", "3"), Obj("doc", "4")}

	for _, d := range docs {
		if ok, err := old.Check(ctx, d, "viewer", a); err != nil || !ok {
			t.Fatalf("old schema: Check(%s) = %v, %v; want true", d, ok, err)
		}
	}

	want := map[Object]bool{Obj("doc", "4"): true}
	var items []CheckItem
	for _, d := range docs {
		ok, err := e.Check(ctx, d, "viewer", a)
		if err != nil || ok != want[d] {
			t.Errorf("Check(%s) = %v, %v; want %v", d, ok, err, want[d])
		}
		items = append(items, CheckItem{Object: d, Permission: "viewer", Subject: a})
	}
	results, err := e.CheckBulk(ctx, items)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range results {
		if r.Err != nil || r.Allowed != want[docs[i]] {
			t.Errorf("CheckBulk(%s) = %+v; want %v", docs[i], r, want[docs[i]])
		}
	}

	objs, err := e.ListObjects(ctx, "doc", "viewer", a)
	if err != nil || !slices.Equal(objs, []Object{Obj("doc", "4")}) {
		t.Errorf("ListObjects = %v, %v; want [doc:4]", objs, err)
	}

	for _, d := range docs {
		set, err := e.ListSubjects(ctx, d, "viewer", "user")
		if err != nil {
			t.Fatal(err)
		}
		if set.All || set.Contains(a) != want[d] {
			t.Errorf("ListSubjects(%s) = %+v", d, set)
		}
	}

	for _, d := range docs[:3] {
		tree, err := e.Expand(ctx, d, "viewer")
		if err != nil {
			t.Fatal(err)
		}
		if leaves := treeLeaves(tree); len(leaves) != 0 {
			t.Errorf("Expand(%s) leaves = %v; want none", d, leaves)
		}
	}
}

func treeLeaves(t *UsersetTree) []Subject {
	if t.Op == TreeLeaf {
		return []Subject{t.Subject}
	}
	var out []Subject
	for _, c := range t.Children {
		out = append(out, treeLeaves(c)...)
	}
	return out
}

func TestQueryRejectsUndefinedSubjectRelation(t *testing.T) {
	ctx := context.Background()
	_, e := schemaChangeEngines(t)
	s := Userset("user", "a", "viewer")
	if ok, err := e.Check(ctx, Obj("doc", "4"), "viewer", s); ok || !errors.Is(err, ErrUnknownRelation) {
		t.Errorf("Check = %v, %v; want ErrUnknownRelation", ok, err)
	}
	if objs, err := e.ListObjects(ctx, "doc", "viewer", s); objs != nil || !errors.Is(err, ErrUnknownRelation) {
		t.Errorf("ListObjects = %v, %v; want ErrUnknownRelation", objs, err)
	}
	if ok, err := e.Check(ctx, Obj("doc", "4"), "viewer", Userset("doc", "4", "viewer")); err != nil || !ok {
		t.Errorf("Check(doc:4#viewer) = %v, %v; want true", ok, err)
	}
}
