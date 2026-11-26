package rebac

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

func granted(t *testing.T, e *Engine, o Object, rel string, s Subject) bool {
	t.Helper()
	ok, err := e.Check(context.Background(), o, rel, s)
	if err != nil && !errors.Is(err, ErrExclusionCycle) {
		t.Fatalf("Check(%s#%s@%s): %v", o, rel, s, err)
	}
	return ok
}

func TestListMatchesCheck(t *testing.T) {
	seeds := 150
	if testing.Short() {
		seeds = 30
	}
	var objects, subjects, all int
	for seed := range seeds {
		rng := rand.New(rand.NewPCG(uint64(seed), 2))
		w := randomWorld(t, rng)
		opts := []Option{WithMaxDepth(1000), WithMaxEvaluations(1 << 24)}
		if seed%2 == 1 {
			opts = append(opts, WithConcurrency(4))
		}
		e := w.engine(t, opts...)
		ctx := context.Background()
		usersets := []string{"a#r1", "b#r2"}

		for _, typ := range worldTypes {
			for _, rel := range worldRelations {
				for _, sub := range w.subjects() {
					got, err := e.ListObjects(ctx, typ, rel, sub)
					if err != nil {
						t.Fatalf("seed %d: ListObjects(%s, %s, %s): %v", seed, typ, rel, sub, err)
					}
					var want []Object
					for _, o := range w.objects {
						if o.Type == typ && granted(t, e, o, rel, sub) {
							want = append(want, o)
						}
					}
					if !slices.Equal(got, want) {
						t.Fatalf("seed %d: ListObjects(%s, %s, %s) = %v, want %v", seed, typ, rel, sub, got, want)
					}
					objects += len(got)
				}
			}
		}

		for _, o := range w.objects {
			for _, rel := range worldRelations {
				set, err := e.ListSubjects(ctx, o, rel, "user")
				if err != nil {
					t.Fatalf("seed %d: ListSubjects(%s#%s, user): %v", seed, o, rel, err)
				}
				for _, u := range append(slices.Clone(w.users), Sub("user", "fresh"), Sub("user", "unnamed0")) {
					if got, want := set.Contains(u), granted(t, e, o, rel, u); got != want {
						t.Fatalf("seed %d: ListSubjects(%s#%s, user) = %+v: contains %s = %v, Check = %v", seed, o, rel, set, u, got, want)
					}
				}
				for _, u := range append(slices.Clone(set.Subjects), set.Except...) {
					if !slices.Contains(w.users, u) {
						t.Fatalf("seed %d: ListSubjects(%s#%s, user) lists unknown %s", seed, o, rel, u)
					}
				}
				if set.All {
					all++
				}
				subjects += len(set.Subjects)

				for _, spec := range usersets {
					set, err := e.ListSubjects(ctx, o, rel, spec)
					if err != nil {
						t.Fatalf("seed %d: ListSubjects(%s#%s, %s): %v", seed, o, rel, spec, err)
					}
					var want []Subject
					typ, urel := spec[:1], spec[2:]
					for _, x := range w.objects {
						if s := Userset(x.Type, x.ID, urel); x.Type == typ && granted(t, e, o, rel, s) {
							want = append(want, s)
						}
					}
					if set.All || !slices.Equal(set.Subjects, want) {
						t.Fatalf("seed %d: ListSubjects(%s#%s, %s) = %+v, want %v", seed, o, rel, spec, set, want)
					}
					subjects += len(set.Subjects)
				}
			}
		}
	}
	if objects == 0 || subjects == 0 || all == 0 {
		t.Fatalf("generator does not cover lists: %d objects, %d subjects, %d wildcards", objects, subjects, all)
	}
	t.Logf("listed %d objects, %d subjects, %d wildcard sets", objects, subjects, all)
}

func TestListSubjectsWildcardExceptions(t *testing.T) {
	e := newEngine(t,
		"folder:pub#viewer@user:*",
		"doc:d#parent@folder:pub",
		"doc:d#banned@user:mallory",
		"doc:d#cleared@user:alice",
		"doc:d#cleared@user:mallory",
	)
	ctx := context.Background()
	set, err := e.ListSubjects(ctx, Obj("doc", "d"), "viewer", "user")
	if err != nil {
		t.Fatal(err)
	}
	if !set.All || !slices.Equal(set.Except, []Subject{Sub("user", "mallory")}) || set.Subjects != nil {
		t.Errorf("viewers = %+v, want everyone but mallory", set)
	}
	set, err = e.ListSubjects(ctx, Obj("doc", "d"), "view_secret", "user")
	if err != nil {
		t.Fatal(err)
	}
	if set.All || !slices.Equal(set.Subjects, []Subject{Sub("user", "alice")}) {
		t.Errorf("view_secret = %+v, want alice", set)
	}
	objs, err := e.ListObjects(ctx, "doc", "viewer", Sub("user", "anyone"))
	if err != nil || !slices.Equal(objs, []Object{Obj("doc", "d")}) {
		t.Errorf("ListObjects for anyone = %v, %v", objs, err)
	}
	objs, err = e.ListObjects(ctx, "doc", "viewer", Sub("user", "mallory"))
	if err != nil || len(objs) != 0 {
		t.Errorf("ListObjects for mallory = %v, %v", objs, err)
	}
}

func TestListValidatesInput(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	if _, err := e.ListObjects(ctx, "doc", "nope", Sub("user", "a")); !errors.Is(err, ErrUnknownRelation) {
		t.Errorf("unknown permission: %v", err)
	}
	if _, err := e.ListObjects(ctx, "doc", "viewer", AllOf("user")); !errors.Is(err, ErrInvalidTuple) {
		t.Errorf("wildcard subject: %v", err)
	}
	for _, spec := range []string{"robot", "user:*", "group#nope", ""} {
		if _, err := e.ListSubjects(ctx, Obj("doc", "d"), "viewer", spec); !errors.Is(err, ErrUnknownRelation) {
			t.Errorf("subject type %q: %v", spec, err)
		}
	}
	if _, err := e.ListSubjects(ctx, Obj("doc", "*"), "viewer", "user"); !errors.Is(err, ErrInvalidTuple) {
		t.Errorf("wildcard object: %v", err)
	}
}

func TestListFailsClosed(t *testing.T) {
	ctx := context.Background()
	e, _ := NewEngine(driveSchema(t), NewMemoryStore(), WithMaxEvaluations(20))
	for i := range 30 {
		write(t, e, fmt.Sprintf("group:g%d#member@group:g%d#member", i+1, i), fmt.Sprintf("doc:d%d#viewer@group:g%d#member", i, i))
	}
	if _, err := e.ListObjects(ctx, "doc", "viewer", Userset("group", "g0", "member")); !errors.Is(err, ErrTooComplex) {
		t.Errorf("ListObjects over a long chain: %v, want ErrTooComplex", err)
	}
	if _, err := e.ListSubjects(ctx, Obj("group", "g29"), "member", "group#member"); !errors.Is(err, ErrTooComplex) {
		t.Errorf("ListSubjects over a long chain: %v, want ErrTooComplex", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	e = newEngine(t, "doc:d#viewer@user:alice")
	if _, err := e.ListObjects(cancelled, "doc", "viewer", Sub("user", "alice")); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled ListObjects: %v", err)
	}
	if _, err := e.ListSubjects(cancelled, Obj("doc", "d"), "viewer", "user"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled ListSubjects: %v", err)
	}

	e, _ = NewEngine(driveSchema(t), &failingStore{MemoryStore: NewMemoryStore(), failObject: Obj("doc", "d")})
	write(t, e, "doc:d#viewer@user:alice")
	if _, err := e.ListObjects(ctx, "doc", "viewer", Sub("user", "alice")); !errors.Is(err, errStore) {
		t.Errorf("ListObjects with a failing store: %v", err)
	}
	if _, err := e.ListSubjects(ctx, Obj("doc", "d"), "viewer", "user"); !errors.Is(err, errStore) {
		t.Errorf("ListSubjects with a failing store: %v", err)
	}
}
