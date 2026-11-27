package rebac

import (
	"context"
	"testing"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observetest"
)

func TestObserver(t *testing.T) {
	const secret = "ctx-SECRET-55e1"
	s, err := NewSchema(
		Caveat("flag", func(args map[string]any) (bool, error) { return args["v"].(bool), nil }, Param{"v", ParamBool}),
		Caveat("code", func(args map[string]any) (bool, error) { return args["code"] == secret, nil }, Param{"code", ParamString}),
		Type("user"),
		Type("doc", Relation("viewer", Direct("user", "user with flag", "user with code"))),
	)
	if err != nil {
		t.Fatal(err)
	}
	rec := &observetest.Recorder{}
	store := &failingStore{MemoryStore: NewMemoryStore(), failObject: Obj("doc", "broken")}
	e, err := NewEngine(s, store, WithObserver(rec), WithCheckCache(16))
	if err != nil {
		t.Fatal(err)
	}
	write(t, e, "doc:1#viewer@user:alice", "doc:1#viewer@user:carol[flag]", "doc:1#viewer@user:dave[code]")
	ctx := context.Background()
	check := func(obj Object, rel, user string, opts ...QueryOption) {
		_, _ = e.Check(ctx, obj, rel, Sub("user", user), opts...)
	}

	check(Obj("doc", "1"), "viewer", "alice")
	check(Obj("doc", "1"), "viewer", "alice")
	check(Obj("doc", "1"), "viewer", "bob")
	check(Obj("doc", "1"), "viewer", "carol")
	check(Obj("doc", "1"), "viewer", "dave", WithContext(map[string]any{"code": secret}))
	check(Obj("doc", "1"), "editor", "alice")
	check(Obj("doc", "broken"), "viewer", "alice")
	if _, err := e.CheckBulk(ctx, []CheckItem{{Obj("doc", "1"), "viewer", Sub("user", "bob")}}); err != nil {
		t.Fatal(err)
	}

	got := rec.Take(t)
	evaluated := []bool{true, false, true, true, true, false, true, false}
	for i := range got {
		if i < len(evaluated) && (got[i].Evaluations > 0) != evaluated[i] {
			t.Errorf("event %d: %d evaluations", i, got[i].Evaluations)
		}
		got[i].Evaluations = 0
	}
	ev := func(obj, rel string, d authent.Decision) authent.Event {
		return authent.Event{Kind: authent.KindAuthorization, Outcome: authent.OutcomeSuccess, ObjectType: obj, Relation: rel, Decision: d}
	}
	fail := func(obj, rel string, r authent.Reason) authent.Event {
		return authent.Event{Kind: authent.KindAuthorization, Outcome: authent.OutcomeError, ObjectType: obj, Relation: rel, Reason: r}
	}
	want := []authent.Event{
		ev("doc", "viewer", authent.DecisionAllowed),
		ev("doc", "viewer", authent.DecisionAllowed),
		ev("doc", "viewer", authent.DecisionDenied),
		ev("doc", "viewer", authent.DecisionConditional),
		ev("doc", "viewer", authent.DecisionAllowed),
		fail("doc", "editor", authent.ReasonUnknownRelation),
		fail("doc", "viewer", ""),
		ev("doc", "viewer", authent.DecisionDenied),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	observetest.NoSecrets(t, got, secret, "carol", "dave")
}
