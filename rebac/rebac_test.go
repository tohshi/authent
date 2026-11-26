package rebac

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"
	"testing"
)

func driveSchema(t testing.TB) *Schema {
	t.Helper()
	s, err := NewSchema(
		Type("user"),
		Type("group",
			Relation("member", Direct("user", "group#member")),
		),
		Type("folder",
			Relation("owner", Direct("user")),
			Relation("parent", Direct("folder")),
			Relation("viewer", Union(
				Direct("user", "group#member", "user:*"),
				Computed("owner"),
				TupleToUserset("parent", "viewer"),
			)),
		),
		Type("doc",
			Relation("parent", Direct("folder")),
			Relation("owner", Direct("user")),
			Relation("editor", Union(Direct("user", "group#member"), Computed("owner"))),
			Relation("banned", Direct("user")),
			Relation("cleared", Direct("user")),
			Relation("viewer", Exclusion(
				Union(
					Direct("user", "group#member", "user:*"),
					Computed("editor"),
					TupleToUserset("parent", "viewer"),
				),
				Computed("banned"),
			)),
			Relation("view_secret", Intersection(Computed("viewer"), Computed("cleared"))),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newEngine(t testing.TB, tuples ...string) *Engine {
	t.Helper()
	e, err := NewEngine(driveSchema(t), NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	write(t, e, tuples...)
	return e
}

func write(t testing.TB, e *Engine, tuples ...string) {
	t.Helper()
	var ts []Tuple
	for _, s := range tuples {
		ts = append(ts, MustParseTuple(s))
	}
	if _, err := e.Write(context.Background(), ts, nil); err != nil {
		t.Fatal(err)
	}
}

type checkCase struct {
	object, permission, subject string
	want                        bool
}

func runChecks(t *testing.T, e *Engine, cases []checkCase) {
	t.Helper()
	for _, tc := range cases {
		obj, err := ParseObject(tc.object)
		if err != nil {
			t.Fatal(err)
		}
		sub, err := ParseSubject(tc.subject)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Check(context.Background(), obj, tc.permission, sub)
		if err != nil {
			t.Errorf("Check(%s#%s@%s) error: %v", tc.object, tc.permission, tc.subject, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Check(%s#%s@%s) = %v, want %v", tc.object, tc.permission, tc.subject, got, tc.want)
		}
	}
}

func TestCheck(t *testing.T) {
	e := newEngine(t,
		// groups: eng contains backend, backend contains bob
		"group:eng#member@user:alice",
		"group:eng#member@group:backend#member",
		"group:backend#member@user:bob",
		// folders: root > projects; carol owns root
		"folder:root#owner@user:carol",
		"folder:projects#parent@folder:root",
		"folder:projects#viewer@group:eng#member",
		"folder:public#viewer@user:*",
		// docs
		"doc:design#parent@folder:projects",
		"doc:design#owner@user:dave",
		"doc:design#banned@user:bob",
		"doc:design#cleared@user:alice",
		"doc:design#cleared@user:dave",
		"doc:handbook#parent@folder:public",
	)
	runChecks(t, e, []checkCase{
		// direct and nested groups
		{"group:eng", "member", "user:alice", true},
		{"group:eng", "member", "user:bob", true},
		{"group:backend", "member", "user:alice", false},
		{"group:eng", "member", "group:backend#member", true},
		{"group:eng", "member", "group:eng#member", true}, // a userset contains itself
		// computed and tuple-to-userset through two folder levels
		{"folder:root", "viewer", "user:carol", true},
		{"folder:projects", "viewer", "user:carol", true},
		{"doc:design", "viewer", "user:carol", true},
		{"doc:design", "viewer", "user:alice", true},
		{"doc:design", "viewer", "user:dave", true}, // owner -> editor -> viewer
		{"doc:design", "editor", "user:dave", true},
		{"doc:design", "editor", "user:alice", false},
		{"doc:design", "viewer", "user:eve", false},
		// exclusion: bob is in eng but banned from the doc
		{"folder:projects", "viewer", "user:bob", true},
		{"doc:design", "viewer", "user:bob", false},
		// intersection
		{"doc:design", "view_secret", "user:alice", true},
		{"doc:design", "view_secret", "user:carol", false}, // viewer, not cleared
		// wildcard
		{"folder:public", "viewer", "user:anyone", true},
		{"doc:handbook", "viewer", "user:anyone", true},
		{"doc:handbook", "viewer", "group:eng#member", false}, // wildcards match objects, not usersets
		{"doc:design", "viewer", "user:anyone", false},
		// userset subjects
		{"folder:projects", "viewer", "group:eng#member", true},
		{"doc:design", "viewer", "group:eng#member", true},
	})
}

func TestCyclicGroups(t *testing.T) {
	e := newEngine(t,
		"group:a#member@group:b#member",
		"group:b#member@group:a#member",
		"group:b#member@user:bob",
	)
	runChecks(t, e, []checkCase{
		{"group:a", "member", "user:bob", true},
		{"group:b", "member", "user:bob", true},
		{"group:a", "member", "user:eve", false},
		{"group:b", "member", "user:eve", false},
	})
}

func TestDeleteRevokes(t *testing.T) {
	e := newEngine(t, "doc:d#owner@user:alice")
	ctx := context.Background()
	if ok, _ := e.Check(ctx, Obj("doc", "d"), "viewer", Sub("user", "alice")); !ok {
		t.Fatal("expected access")
	}
	if _, err := e.Write(ctx, nil, []Tuple{MustParseTuple("doc:d#owner@user:alice")}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.Check(ctx, Obj("doc", "d"), "viewer", Sub("user", "alice")); ok {
		t.Fatal("access survived delete")
	}
}

func TestWriteValidation(t *testing.T) {
	e := newEngine(t)
	for _, tc := range []struct {
		tuple string
		want  error
	}{
		{"doc:d#owner@group:eng#member", ErrSubjectNotAllowed}, // owner allows only users
		{"doc:d#owner@user:*", ErrSubjectNotAllowed},           // no wildcard on owner
		{"doc:d#view_secret@user:alice", ErrSubjectNotAllowed}, // computed permission
		{"doc:d#parent@folder:f#viewer", ErrSubjectNotAllowed}, // userset not allowed
		{"doc:d#unknown@user:alice", ErrUnknownRelation},
		{"sheet:d#owner@user:alice", ErrUnknownRelation},
		{"doc:d#editor@group:eng", ErrSubjectNotAllowed}, // must be group#member
	} {
		_, err := e.Write(context.Background(), []Tuple{MustParseTuple(tc.tuple)}, nil)
		if !errors.Is(err, tc.want) {
			t.Errorf("Write(%s) = %v, want %v", tc.tuple, err, tc.want)
		}
	}

	// A batch with one invalid tuple writes nothing.
	ctx := context.Background()
	_, err := e.Write(ctx, []Tuple{MustParseTuple("doc:d#owner@user:alice"), MustParseTuple("doc:d#owner@user:*")}, nil)
	if err == nil {
		t.Fatal("batch with invalid tuple succeeded")
	}
	if ok, _ := e.Check(ctx, Obj("doc", "d"), "owner", Sub("user", "alice")); ok {
		t.Fatal("partial batch was applied")
	}
}

func TestParseTuple(t *testing.T) {
	for _, s := range []string{
		"doc:readme#viewer@user:alice",
		"doc:readme#viewer@group:eng#member",
		"doc:readme#viewer@user:*",
		"doc:a-b_c.d|e#viewer@user:日本語",
	} {
		tp, err := ParseTuple(s)
		if err != nil {
			t.Fatalf("ParseTuple(%q) = %v", s, err)
		}
		if tp.String() != s {
			t.Fatalf("round trip %q -> %q", s, tp.String())
		}
	}
	for _, s := range []string{
		"", "doc:readme", "doc:readme#viewer", "doc#viewer@user:alice", "doc:#viewer@user:alice",
		"Doc:readme#viewer@user:alice", "doc:readme#Viewer@user:alice", "doc:*#viewer@user:alice",
		"doc:readme#viewer@user:*#member", "doc:read me#viewer@user:alice", "doc:a#viewer@user:b@c",
		"doc:a#viewer@user", "doc:a#viewer@user:al*ce", "doc:a#viewer@group:eng#",
		"doc:a\x00#viewer@user:alice", fmt.Sprintf("doc:%0300d#viewer@user:alice", 0),
	} {
		if _, err := ParseTuple(s); !errors.Is(err, ErrInvalidTuple) {
			t.Errorf("ParseTuple(%q) = %v, want ErrInvalidTuple", s, err)
		}
	}
}

func TestCheckValidatesInput(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	if _, err := e.Check(ctx, Obj("doc", "d"), "nope", Sub("user", "a")); !errors.Is(err, ErrUnknownRelation) {
		t.Errorf("unknown permission: %v", err)
	}
	if _, err := e.Check(ctx, Obj("doc", "d"), "viewer", AllOf("user")); !errors.Is(err, ErrInvalidTuple) {
		t.Errorf("wildcard subject: %v", err)
	}
	if _, err := e.Check(ctx, Obj("doc", ""), "viewer", Sub("user", "a")); !errors.Is(err, ErrInvalidTuple) {
		t.Errorf("empty object id: %v", err)
	}
}

func TestSchemaValidation(t *testing.T) {
	for name, types := range map[string][]Definition{
		"unknown direct type":    {Type("doc", Relation("viewer", Direct("user")))},
		"unknown userset rel":    {Type("user"), Type("doc", Relation("viewer", Direct("user#member")))},
		"unknown computed":       {Type("doc", Relation("viewer", Computed("editor")))},
		"empty direct":           {Type("doc", Relation("viewer", Direct()))},
		"empty union":            {Type("doc", Relation("viewer", Union()))},
		"nil rewrite":            {Type("doc", Relation("viewer", nil))},
		"duplicate type":         {Type("user"), Type("user")},
		"duplicate relation":     {Type("user"), Type("doc", Relation("r", Direct("user")), Relation("r", Direct("user")))},
		"bad type name":          {Type("User")},
		"bad relation name":      {Type("user"), Type("doc", Relation("view-er", Direct("user")))},
		"computed cycle":         {Type("doc", Relation("a", Computed("b")), Relation("b", Union(Computed("a"))))},
		"self computed":          {Type("doc", Relation("a", Computed("a")))},
		"ttu unknown tupleset":   {Type("doc", Relation("viewer", TupleToUserset("parent", "viewer")))},
		"ttu computed tupleset":  {Type("user"), Type("doc", Relation("p", Direct("user")), Relation("q", Computed("p")), Relation("v", TupleToUserset("q", "v")))},
		"ttu userset tupleset":   {Type("group", Relation("member", Direct("group"))), Type("doc", Relation("p", Direct("group#member")), Relation("v", TupleToUserset("p", "member")))},
		"ttu no target relation": {Type("folder"), Type("doc", Relation("parent", Direct("folder")), Relation("v", TupleToUserset("parent", "viewer")))},
	} {
		if _, err := NewSchema(types...); !errors.Is(err, ErrInvalidSchema) {
			t.Errorf("%s: err = %v, want ErrInvalidSchema", name, err)
		}
	}
}

func TestDepthLimit(t *testing.T) {
	s := driveSchema(t)
	e, err := NewEngine(s, NewMemoryStore(), WithMaxDepth(5))
	if err != nil {
		t.Fatal(err)
	}
	// g0 <- g1 <- ... <- g9 <- bob
	for i := range 9 {
		write(t, e, fmt.Sprintf("group:g%d#member@group:g%d#member", i, i+1))
	}
	write(t, e, "group:g9#member@user:bob")
	ok, err := e.Check(context.Background(), Obj("group", "g0"), "member", Sub("user", "bob"))
	if ok || !errors.Is(err, ErrTooComplex) {
		t.Fatalf("Check = %v, %v; want false, ErrTooComplex", ok, err)
	}
	ok, err = e.Check(context.Background(), Obj("group", "g7"), "member", Sub("user", "bob"))
	if !ok || err != nil {
		t.Fatalf("shallow Check = %v, %v", ok, err)
	}
}

func TestEvaluationLimit(t *testing.T) {
	e, _ := NewEngine(driveSchema(t), NewMemoryStore(), WithMaxEvaluations(20))
	for i := range 50 {
		write(t, e, fmt.Sprintf("group:big#member@group:g%d#member", i))
	}
	_, err := e.Check(context.Background(), Obj("group", "big"), "member", Sub("user", "bob"))
	if !errors.Is(err, ErrTooComplex) {
		t.Fatalf("err = %v", err)
	}
}

// failingStore fails reads for one object, optionally only for one relation.
type failingStore struct {
	*MemoryStore
	failObject   Object
	failRelation string
}

var errStore = errors.New("store unavailable")

func (f *failingStore) Read(ctx context.Context, rev Revision, filter Filter) iter.Seq2[Tuple, error] {
	if filter.ObjectType == f.failObject.Type && filter.ObjectID == f.failObject.ID &&
		(f.failRelation == "" || f.failRelation == filter.Relation) {
		return func(yield func(Tuple, error) bool) { yield(Tuple{}, errStore) }
	}
	return f.MemoryStore.Read(ctx, rev, filter)
}

func TestExcludedBranchErrorDenies(t *testing.T) {
	mem := NewMemoryStore()
	e, _ := NewEngine(driveSchema(t), &failingStore{MemoryStore: mem, failObject: Obj("doc", "d"), failRelation: "banned"})
	write(t, e, "doc:d#owner@user:dave")
	// dave is granted by the base branch, but whether he is banned cannot be
	// determined: the check must deny.
	ok, err := e.Check(context.Background(), Obj("doc", "d"), "viewer", Sub("user", "dave"))
	if ok || !errors.Is(err, errStore) {
		t.Fatalf("Check = %v, %v; want false, errStore", ok, err)
	}
	// Relations that do not involve the failing read still work.
	ok, err = e.Check(context.Background(), Obj("doc", "d"), "editor", Sub("user", "dave"))
	if !ok || err != nil {
		t.Fatalf("editor Check = %v, %v", ok, err)
	}
}

func TestStoreErrorsFailClosed(t *testing.T) {
	store := &failingStore{MemoryStore: NewMemoryStore(), failObject: Obj("group", "broken")}
	e, _ := NewEngine(driveSchema(t), store)
	write(t, e,
		"doc:d#viewer@group:broken#member",
		"doc:d#viewer@group:ok#member",
		"group:ok#member@user:alice",
		"doc:d#owner@user:dave",
	)
	ctx := context.Background()

	// Grant found through another branch: true, no error.
	ok, err := e.Check(ctx, Obj("doc", "d"), "viewer", Sub("user", "alice"))
	if !ok || err != nil {
		t.Fatalf("alice: %v, %v", ok, err)
	}
	// No grant and a failing branch: false with the error.
	ok, err = e.Check(ctx, Obj("doc", "d"), "viewer", Sub("user", "eve"))
	if ok || !errors.Is(err, errStore) {
		t.Fatalf("eve: %v, %v", ok, err)
	}
}

func TestContextCanceled(t *testing.T) {
	e := newEngine(t, "doc:d#owner@user:alice")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err := e.Check(ctx, Obj("doc", "d"), "viewer", Sub("user", "alice"))
	if ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("Check = %v, %v", ok, err)
	}
}

func TestConcurrentWritesAndChecks(t *testing.T) {
	e := newEngine(t, "folder:root#owner@user:carol")
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 100 {
				tp := MustParseTuple(fmt.Sprintf("doc:d%d_%d#parent@folder:root", i, j))
				if _, err := e.Write(ctx, []Tuple{tp}, nil); err != nil {
					t.Error(err)
					return
				}
				ok, err := e.Check(ctx, tp.Object, "viewer", Sub("user", "carol"))
				if !ok || err != nil {
					t.Errorf("Check = %v, %v", ok, err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestMemoryStoreRead(t *testing.T) {
	e := newEngine(t,
		"doc:a#owner@user:alice",
		"doc:b#owner@user:alice",
		"doc:b#editor@user:bob",
	)
	alice := Sub("user", "alice")
	n := 0
	for tp, err := range e.store.Read(context.Background(), 1, Filter{Subject: &alice}) {
		if err != nil || tp.Subject != alice {
			t.Fatalf("unexpected %v, %v", tp, err)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("reverse lookup found %d tuples, want 2", n)
	}
}
