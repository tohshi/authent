package rebac

import (
	"context"
	"errors"
	"testing"
)

// exclusionEngine's doc viewer relation subtracts banned, which may
// contain doc viewers again.
func exclusionEngine(t *testing.T, tuples ...string) *Engine {
	t.Helper()
	s, err := NewSchema(
		Type("user"),
		Type("group", Relation("member", Direct("user", "group#member"))),
		Type("doc",
			Relation("banned", Direct("user", "group#member", "doc#viewer")),
			Relation("viewer", Exclusion(Direct("user"), Computed("banned"))),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(s, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	write(t, e, tuples...)
	return e
}

func wantCheck(t *testing.T, e *Engine, object, permission, subject string, want bool, wantErr error) {
	t.Helper()
	obj, err := ParseObject(object)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := ParseSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Check(context.Background(), obj, permission, sub)
	if got != want || !errors.Is(err, wantErr) || (wantErr == nil) != (err == nil) {
		t.Errorf("Check(%s#%s@%s) = %v, %v; want %v, %v", object, permission, subject, got, err, want, wantErr)
	}
}

func TestExclusionCycleNeverGrants(t *testing.T) {
	// bob is a viewer exactly when he is not one.
	e := exclusionEngine(t,
		"doc:d#viewer@user:bob",
		"doc:d#banned@doc:d#viewer",
	)
	wantCheck(t, e, "doc:d", "viewer", "user:bob", false, ErrExclusionCycle)
	wantCheck(t, e, "doc:d", "banned", "user:bob", false, ErrExclusionCycle)
	wantCheck(t, e, "doc:d", "viewer", "user:alice", false, nil)
	wantCheck(t, e, "doc:d", "banned", "user:alice", false, nil)
}

func TestExclusionCycleDecidedElsewhere(t *testing.T) {
	e := exclusionEngine(t,
		"doc:d#viewer@user:bob",
		"doc:d#banned@doc:d#viewer",
		"doc:d#banned@group:g#member",
		"group:g#member@user:bob",
	)
	wantCheck(t, e, "doc:d", "viewer", "user:bob", false, nil)
	wantCheck(t, e, "doc:d", "banned", "user:bob", true, nil)
}

func TestCycleInsideSubtractedSide(t *testing.T) {
	e := exclusionEngine(t,
		"doc:d#viewer@user:bob",
		"doc:d#banned@group:a#member",
		"group:a#member@group:b#member",
		"group:b#member@group:a#member",
	)
	wantCheck(t, e, "doc:d", "viewer", "user:bob", true, nil)
	wantCheck(t, e, "doc:d", "banned", "user:bob", false, nil)
}

func TestCycleDoesNotCancelSubtraction(t *testing.T) {
	// Evaluating both reaches gate while member is on the path, but member
	// is true through extra, so bob is blocked and gate excludes him.
	s, err := NewSchema(
		Type("user"),
		Type("doc",
			Relation("extra", Direct("user")),
			Relation("member", Union(Direct("doc#gate"), Computed("extra"))),
			Relation("blocked", Direct("doc#member")),
			Relation("gate", Exclusion(Direct("user"), Computed("blocked"))),
			Relation("both", Intersection(Computed("member"), Computed("gate"))),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(s, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	write(t, e,
		"doc:d#gate@user:bob",
		"doc:d#extra@user:bob",
		"doc:d#member@doc:d#gate",
		"doc:d#blocked@doc:d#member",
	)
	wantCheck(t, e, "doc:d", "both", "user:bob", false, nil)
	wantCheck(t, e, "doc:d", "gate", "user:bob", false, nil)
	wantCheck(t, e, "doc:d", "member", "user:bob", true, nil)
}

func TestExclusionCycleWithStoreError(t *testing.T) {
	s, err := NewSchema(
		Type("user"),
		Type("doc",
			Relation("banned", Direct("user", "doc#viewer", "doc#other")),
			Relation("other", Direct("user")),
			Relation("viewer", Exclusion(Direct("user"), Computed("banned"))),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	store := &failingStore{MemoryStore: NewMemoryStore(), failObject: Obj("doc", "x")}
	e, _ := NewEngine(s, store)
	write(t, e,
		"doc:d#viewer@user:bob",
		"doc:d#banned@doc:d#viewer",
		"doc:d#banned@doc:x#other",
	)
	wantCheck(t, e, "doc:d", "viewer", "user:bob", false, errStore)
}
