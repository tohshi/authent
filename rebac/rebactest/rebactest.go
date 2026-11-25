// Package rebactest provides a conformance test suite for rebac.TupleStore
// implementations.
//
// Use it to test your own store, or to check rebac.SQLStore against your
// database and driver:
//
//	func TestStore(t *testing.T) {
//		rebactest.TestTupleStore(t, func(t *testing.T) rebac.TupleStore {
//			return newEmptyStore(t)
//		})
//	}
package rebactest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/tohshi/authent/rebac"
)

// TestTupleStore runs the conformance suite as subtests of t. newStore must
// return a new, empty store on every call; it may use t.Cleanup to release
// it.
func TestTupleStore(t *testing.T, newStore func(t *testing.T) rebac.TupleStore) {
	tests := []struct {
		name string
		fn   func(*testing.T, rebac.TupleStore)
	}{
		{"Empty", testEmpty},
		{"WriteAndRead", testWriteAndRead},
		{"Idempotent", testIdempotent},
		{"DeleteThenWrite", testDeleteThenWrite},
		{"Filters", testFilters},
		{"ExactMatch", testExactMatch},
		{"Limits", testLimits},
		{"NestedRead", testNestedRead},
		{"EarlyBreak", testEarlyBreak},
		{"LargeBatch", testLargeBatch},
		{"Concurrent", testConcurrent},
		{"Engine", testEngine},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newStore(t)) })
	}
}

func parse(t *testing.T, tuples ...string) []rebac.Tuple {
	t.Helper()
	out := make([]rebac.Tuple, 0, len(tuples))
	for _, s := range tuples {
		tp, err := rebac.ParseTuple(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tp)
	}
	return out
}

func write(t *testing.T, s rebac.TupleStore, writes, deletes []string) {
	t.Helper()
	if err := s.Write(context.Background(), parse(t, writes...), parse(t, deletes...)); err != nil {
		t.Fatalf("Write(%q, %q): %v", writes, deletes, err)
	}
}

func read(t *testing.T, s rebac.TupleStore, f rebac.Filter) []string {
	t.Helper()
	out := []string{}
	for tp, err := range s.Read(context.Background(), f) {
		if err != nil {
			t.Fatalf("Read(%+v): %v", f, err)
		}
		out = append(out, tp.String())
	}
	slices.Sort(out)
	return out
}

func want(t *testing.T, s rebac.TupleStore, f rebac.Filter, tuples ...string) {
	t.Helper()
	got := read(t, s, f)
	exp := slices.Sorted(slices.Values(tuples))
	if !slices.Equal(got, exp) {
		t.Errorf("Read(%s) =\n\t%q\nwant\n\t%q", describe(f), got, exp)
	}
}

func describe(f rebac.Filter) string {
	s := fmt.Sprintf("type=%q id=%q rel=%q", f.ObjectType, f.ObjectID, f.Relation)
	if f.Subject != nil {
		s += fmt.Sprintf(" subject=%q", f.Subject.String())
	}
	return s
}

func objRel(typ, id, rel string) rebac.Filter {
	return rebac.Filter{ObjectType: typ, ObjectID: id, Relation: rel}
}

func testEmpty(t *testing.T, s rebac.TupleStore) {
	want(t, s, rebac.Filter{})
	want(t, s, objRel("doc", "readme", "viewer"))
}

func testWriteAndRead(t *testing.T, s rebac.TupleStore) {
	write(t, s, []string{
		"doc:readme#viewer@user:alice",
		"doc:readme#viewer@group:eng#member",
		"doc:readme#viewer@user:*",
		"doc:readme#owner@user:bob",
		"doc:other#viewer@user:alice",
	}, nil)
	want(t, s, objRel("doc", "readme", "viewer"),
		"doc:readme#viewer@user:alice",
		"doc:readme#viewer@group:eng#member",
		"doc:readme#viewer@user:*",
	)
	want(t, s, objRel("doc", "readme", "owner"), "doc:readme#owner@user:bob")
	want(t, s, objRel("doc", "missing", "viewer"))

	write(t, s, nil, []string{"doc:readme#viewer@user:alice"})
	want(t, s, objRel("doc", "readme", "viewer"),
		"doc:readme#viewer@group:eng#member",
		"doc:readme#viewer@user:*",
	)
	want(t, s, objRel("doc", "other", "viewer"), "doc:other#viewer@user:alice")
}

func testIdempotent(t *testing.T, s rebac.TupleStore) {
	tp := "doc:readme#viewer@user:alice"
	write(t, s, []string{tp, tp}, nil)
	write(t, s, []string{tp}, nil)
	want(t, s, rebac.Filter{}, tp)

	write(t, s, nil, []string{"doc:readme#viewer@user:missing"})
	write(t, s, nil, []string{tp, tp})
	want(t, s, rebac.Filter{})
	write(t, s, nil, nil)
}

func testDeleteThenWrite(t *testing.T, s rebac.TupleStore) {
	write(t, s, []string{"doc:a#viewer@user:old"}, nil)
	// Deletes are applied before writes, so a tuple in both is present.
	write(t, s,
		[]string{"doc:a#viewer@user:new", "doc:a#viewer@user:both"},
		[]string{"doc:a#viewer@user:old", "doc:a#viewer@user:both"})
	want(t, s, objRel("doc", "a", "viewer"), "doc:a#viewer@user:new", "doc:a#viewer@user:both")
}

func testFilters(t *testing.T, s rebac.TupleStore) {
	all := []string{
		"doc:a#viewer@user:alice",
		"doc:a#viewer@group:eng#member",
		"doc:a#viewer@user:alice#friend",
		"doc:a#owner@user:alice",
		"doc:b#viewer@user:*",
		"doc:b#parent@folder:root",
		"folder:a#viewer@user:alice",
		"group:eng#member@user:alice",
	}
	write(t, s, all, nil)

	alice := rebac.Sub("user", "alice")
	eng := rebac.Userset("group", "eng", "member")
	anyUser := rebac.AllOf("user")
	tests := []struct {
		f    rebac.Filter
		want []string
	}{
		{rebac.Filter{}, all},
		{rebac.Filter{ObjectType: "doc"}, all[:6]},
		{rebac.Filter{ObjectType: "doc", ObjectID: "a"}, all[:4]},
		{objRel("doc", "a", "viewer"), all[:3]},
		{rebac.Filter{ObjectID: "a"}, []string{all[0], all[1], all[2], all[3], all[6]}},
		{rebac.Filter{Relation: "viewer"}, []string{all[0], all[1], all[2], all[4], all[6]}},
		// A subject filter matches the relation exactly, including empty.
		{rebac.Filter{Subject: &alice}, []string{all[0], all[3], all[6], all[7]}},
		{rebac.Filter{ObjectType: "doc", Subject: &alice}, []string{all[0], all[3]}},
		{rebac.Filter{Subject: &eng}, []string{all[1]}},
		{rebac.Filter{Subject: &anyUser}, []string{all[4]}},
		{rebac.Filter{ObjectType: "nope"}, nil},
	}
	for _, tc := range tests {
		want(t, s, tc.f, tc.want...)
	}
}

func testExactMatch(t *testing.T, s rebac.TupleStore) {
	// Stores must compare identifiers byte by byte: no case folding, no
	// Unicode normalization, no prefix or trailing-character matching.
	ids := []string{"alice", "Alice", "ALICE", "alice_", "alic", "café", "café", "ß", "ss"}
	var tuples []string
	for _, id := range ids {
		tuples = append(tuples, "doc:"+id+"#viewer@user:"+id)
	}
	write(t, s, tuples, nil)
	for i, id := range ids {
		want(t, s, objRel("doc", id, "viewer"), tuples[i])
		sub := rebac.Sub("user", id)
		want(t, s, rebac.Filter{Subject: &sub}, tuples[i])
	}

	write(t, s, nil, []string{"doc:Alice#viewer@user:Alice"})
	want(t, s, objRel("doc", "alice", "viewer"), "doc:alice#viewer@user:alice")
	want(t, s, objRel("doc", "Alice", "viewer"))
}

func testLimits(t *testing.T, s rebac.TupleStore) {
	// The longest valid identifiers: 256-byte IDs (here multi-byte) and
	// 64-byte type and relation names.
	id := strings.Repeat("é", 128)
	name := "t" + strings.Repeat("x", 63)
	tp := fmt.Sprintf("%s:%s#%s@%s:%s#%s", name, id, name, name, id, name)
	write(t, s, []string{tp}, nil)
	want(t, s, objRel(name, id, name), tp)
}

func testNestedRead(t *testing.T, s rebac.TupleStore) {
	write(t, s, []string{
		"group:a#member@group:b#member",
		"group:a#member@group:c#member",
		"group:b#member@user:bob",
		"group:c#member@user:carol",
	}, nil)
	var got []string
	ctx := context.Background()
	for outer, err := range s.Read(ctx, objRel("group", "a", "member")) {
		if err != nil {
			t.Fatal(err)
		}
		f := objRel(outer.Subject.Object.Type, outer.Subject.Object.ID, outer.Subject.Relation)
		for inner, err := range s.Read(ctx, f) {
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, inner.String())
		}
	}
	slices.Sort(got)
	if exp := []string{"group:b#member@user:bob", "group:c#member@user:carol"}; !slices.Equal(got, exp) {
		t.Errorf("nested reads = %q, want %q", got, exp)
	}
}

func testEarlyBreak(t *testing.T, s rebac.TupleStore) {
	var tuples []string
	for i := range 10 {
		tuples = append(tuples, fmt.Sprintf("doc:a#viewer@user:u%d", i))
	}
	write(t, s, tuples, nil)
	for range 3 {
		for _, err := range s.Read(context.Background(), objRel("doc", "a", "viewer")) {
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	// The store still works after abandoned iterations.
	write(t, s, []string{"doc:b#viewer@user:x"}, nil)
	want(t, s, objRel("doc", "a", "viewer"), tuples...)
}

func testLargeBatch(t *testing.T, s rebac.TupleStore) {
	var tuples []string
	for i := range 1000 {
		tuples = append(tuples, fmt.Sprintf("doc:d%d#viewer@user:u%d", i%10, i))
	}
	write(t, s, tuples, nil)
	if n := len(read(t, s, rebac.Filter{ObjectType: "doc"})); n != len(tuples) {
		t.Fatalf("read %d tuples, want %d", n, len(tuples))
	}
	write(t, s, nil, tuples)
	want(t, s, rebac.Filter{})
}

func testConcurrent(t *testing.T, s rebac.TupleStore) {
	const workers, perWorker = 8, 25
	ctx := context.Background()
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range perWorker {
				tp := rebac.Tuple{
					Object:   rebac.Obj("doc", fmt.Sprintf("w%d", w)),
					Relation: "viewer",
					Subject:  rebac.Sub("user", fmt.Sprintf("u%d", i)),
				}
				if err := s.Write(ctx, []rebac.Tuple{tp}, nil); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
				found := false
				for got, err := range s.Read(ctx, objRel("doc", tp.Object.ID, "viewer")) {
					if err != nil {
						t.Errorf("Read: %v", err)
						return
					}
					found = found || got == tp
				}
				if !found {
					t.Errorf("%s not found after Write", tp)
					return
				}
			}
		})
	}
	wg.Wait()
	if n := len(read(t, s, rebac.Filter{ObjectType: "doc"})); n != workers*perWorker {
		t.Errorf("read %d tuples, want %d", n, workers*perWorker)
	}
}

func testEngine(t *testing.T, s rebac.TupleStore) {
	schema, err := rebac.NewSchema(
		rebac.Type("user"),
		rebac.Type("group", rebac.Relation("member", rebac.Direct("user", "group#member"))),
		rebac.Type("folder",
			rebac.Relation("owner", rebac.Direct("user")),
			rebac.Relation("viewer", rebac.Union(rebac.Direct("user", "group#member", "user:*"), rebac.Computed("owner"))),
		),
		rebac.Type("doc",
			rebac.Relation("parent", rebac.Direct("folder")),
			rebac.Relation("banned", rebac.Direct("user")),
			rebac.Relation("viewer", rebac.Exclusion(
				rebac.Union(rebac.Direct("user"), rebac.TupleToUserset("parent", "viewer")),
				rebac.Computed("banned"))),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	e, err := rebac.NewEngine(schema, s)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.Write(ctx, parse(t,
		"folder:root#viewer@group:eng#member",
		"folder:root#owner@user:olivia",
		"group:eng#member@group:backend#member",
		"group:backend#member@user:alice",
		"group:backend#member@user:mallory",
		"doc:readme#parent@folder:root",
		"doc:readme#banned@user:mallory",
	), nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		user string
		want bool
	}{
		{"alice", true},
		{"olivia", true},
		{"mallory", false},
		{"Alice", false},
		{"eve", false},
	} {
		got, err := e.Check(ctx, rebac.Obj("doc", "readme"), "viewer", rebac.Sub("user", tc.user))
		if err != nil || got != tc.want {
			t.Errorf("Check(doc:readme#viewer@user:%s) = %v, %v; want %v", tc.user, got, err, tc.want)
		}
	}
}
