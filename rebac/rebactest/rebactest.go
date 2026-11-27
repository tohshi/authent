// Package rebactest provides a conformance test suite for rebac.TupleStore
// implementations.
//
// Use it to test your own store, or to check rebac/sqlstore.Store against your
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
	"errors"
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
		{"Revisions", testRevisions},
		{"SnapshotReads", testSnapshotReads},
		{"UnavailableRevisions", testUnavailableRevisions},
		{"Changes", testChanges},
		{"Prune", testPrune},
		{"Caveats", testCaveats},
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

func write(t *testing.T, s rebac.TupleStore, writes, deletes []string) rebac.Revision {
	t.Helper()
	rev, err := s.Write(context.Background(), parse(t, writes...), parse(t, deletes...))
	if err != nil {
		t.Fatalf("Write(%q, %q): %v", writes, deletes, err)
	}
	return rev
}

func head(t *testing.T, s rebac.TupleStore) rebac.Revision {
	t.Helper()
	rev, err := s.Revision(context.Background())
	if err != nil {
		t.Fatalf("Revision: %v", err)
	}
	return rev
}

func read(t *testing.T, s rebac.TupleStore, f rebac.Filter) []string {
	t.Helper()
	return readAt(t, s, head(t, s), f)
}

func readAt(t *testing.T, s rebac.TupleStore, rev rebac.Revision, f rebac.Filter) []string {
	t.Helper()
	out := []string{}
	for tp, err := range s.Read(context.Background(), rev, f) {
		if err != nil {
			t.Fatalf("Read(%d, %+v): %v", rev, f, err)
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
	rev := head(t, s)
	for outer, err := range s.Read(ctx, rev, objRel("group", "a", "member")) {
		if err != nil {
			t.Fatal(err)
		}
		f := objRel(outer.Subject.Object.Type, outer.Subject.Object.ID, outer.Subject.Relation)
		for inner, err := range s.Read(ctx, rev, f) {
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
	rev := write(t, s, tuples, nil)
	for range 3 {
		for _, err := range s.Read(context.Background(), rev, objRel("doc", "a", "viewer")) {
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
				rev, err := s.Write(ctx, []rebac.Tuple{tp}, nil)
				if err != nil {
					t.Errorf("Write: %v", err)
					return
				}
				found := false
				for got, err := range s.Read(ctx, rev, objRel("doc", tp.Object.ID, "viewer")) {
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
	if _, err := e.Write(ctx, parse(t,
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

func testRevisions(t *testing.T, s rebac.TupleStore) {
	if rev := head(t, s); rev != 0 {
		t.Fatalf("empty store at revision %d, want 0", rev)
	}
	r1 := write(t, s, []string{"doc:a#viewer@user:alice"}, nil)
	r2 := write(t, s, nil, []string{"doc:a#viewer@user:alice"})
	r3 := write(t, s, []string{"doc:a#viewer@user:bob"}, []string{"doc:a#viewer@user:missing"})
	if !(0 < r1 && r1 < r2 && r2 < r3) {
		t.Fatalf("revisions %d, %d, %d do not increase", r1, r2, r3)
	}
	if rev := head(t, s); rev != r3 {
		t.Fatalf("Revision() = %d, want %d", rev, r3)
	}
	if rev := write(t, s, nil, nil); rev != r3 {
		t.Fatalf("empty Write returned %d, want %d", rev, r3)
	}
}

func testSnapshotReads(t *testing.T, s rebac.TupleStore) {
	r1 := write(t, s, []string{"doc:a#viewer@user:alice", "doc:a#viewer@user:bob"}, nil)
	r2 := write(t, s, []string{"doc:a#viewer@user:carol"}, []string{"doc:a#viewer@user:alice"})
	r3 := write(t, s, []string{"doc:a#viewer@user:alice"}, []string{"doc:a#viewer@user:bob"})
	f := objRel("doc", "a", "viewer")
	for _, tc := range []struct {
		rev  rebac.Revision
		want []string
	}{
		{0, []string{}},
		{r1, []string{"doc:a#viewer@user:alice", "doc:a#viewer@user:bob"}},
		{r2, []string{"doc:a#viewer@user:bob", "doc:a#viewer@user:carol"}},
		{r3, []string{"doc:a#viewer@user:alice", "doc:a#viewer@user:carol"}},
	} {
		if got := readAt(t, s, tc.rev, f); !slices.Equal(got, tc.want) {
			t.Errorf("Read at %d = %q, want %q", tc.rev, got, tc.want)
		}
		alice := rebac.Sub("user", "alice")
		var want []string
		for _, w := range tc.want {
			if strings.HasSuffix(w, "@user:alice") {
				want = append(want, w)
			}
		}
		if got := readAt(t, s, tc.rev, rebac.Filter{Subject: &alice}); len(got) != len(want) {
			t.Errorf("reverse Read at %d = %q, want %q", tc.rev, got, want)
		}
	}
}

func readErr(s rebac.TupleStore, rev rebac.Revision) error {
	for _, err := range s.Read(context.Background(), rev, objRel("doc", "a", "viewer")) {
		if err != nil {
			return err
		}
	}
	return nil
}

func changesErr(s rebac.TupleStore, after rebac.Revision) error {
	for _, err := range s.Changes(context.Background(), after) {
		if err != nil {
			return err
		}
	}
	return nil
}

func testUnavailableRevisions(t *testing.T, s rebac.TupleStore) {
	rev := write(t, s, []string{"doc:a#viewer@user:alice"}, nil)
	for _, r := range []rebac.Revision{rev + 1, rev + 1000, 1<<63 - 1, 1 << 63} {
		if err := readErr(s, r); !errors.Is(err, rebac.ErrFutureRevision) {
			t.Errorf("Read at %d: %v, want ErrFutureRevision", r, err)
		}
		if err := changesErr(s, r); !errors.Is(err, rebac.ErrFutureRevision) {
			t.Errorf("Changes after %d: %v, want ErrFutureRevision", r, err)
		}
	}
}

func changes(t *testing.T, s rebac.TupleStore, after rebac.Revision) []string {
	t.Helper()
	out := []string{}
	for c, err := range s.Changes(context.Background(), after) {
		if err != nil {
			t.Fatalf("Changes(%d): %v", after, err)
		}
		out = append(out, fmt.Sprintf("%d %s %s", c.Revision, c.Op, c.Tuple))
	}
	return out
}

func testChanges(t *testing.T, s rebac.TupleStore) {
	r1 := write(t, s, []string{"doc:a#viewer@user:bob", "doc:a#viewer@user:alice", "doc:b#owner@user:alice"}, nil)
	r2 := write(t, s,
		[]string{"doc:a#viewer@user:alice", "doc:a#viewer@user:carol", "doc:a#viewer@user:dave"},
		[]string{"doc:a#viewer@user:bob", "doc:b#owner@user:alice", "doc:a#viewer@user:dave", "doc:a#viewer@user:missing"})
	rNoop := write(t, s, []string{"doc:a#viewer@user:alice"}, []string{"doc:a#viewer@user:missing"})
	r4 := write(t, s, nil, []string{"doc:a#viewer@user:carol"})
	all := []string{
		fmt.Sprintf("%d write doc:a#viewer@user:alice", r1),
		fmt.Sprintf("%d write doc:a#viewer@user:bob", r1),
		fmt.Sprintf("%d write doc:b#owner@user:alice", r1),
		fmt.Sprintf("%d delete doc:a#viewer@user:bob", r2),
		fmt.Sprintf("%d delete doc:b#owner@user:alice", r2),
		fmt.Sprintf("%d write doc:a#viewer@user:carol", r2),
		fmt.Sprintf("%d write doc:a#viewer@user:dave", r2),
		fmt.Sprintf("%d delete doc:a#viewer@user:carol", r4),
	}
	for _, tc := range []struct {
		after rebac.Revision
		want  []string
	}{
		{0, all},
		{r1, all[3:]},
		{r2, all[7:]},
		{rNoop, all[7:]},
		{r4, []string{}},
	} {
		if got := changes(t, s, tc.after); !slices.Equal(got, tc.want) {
			t.Errorf("Changes(%d) =\n\t%q\nwant\n\t%q", tc.after, got, tc.want)
		}
	}
}

// Pruner is implemented by stores that can discard history, such as
// rebac.MemoryStore and rebac/sqlstore.Store. The Prune test runs only for them.
type Pruner interface {
	Prune(ctx context.Context, before rebac.Revision) error
}

func testPrune(t *testing.T, s rebac.TupleStore) {
	p, ok := s.(Pruner)
	if !ok {
		t.Skip("store does not implement Prune")
	}
	ctx := context.Background()
	r1 := write(t, s, []string{"doc:a#viewer@user:alice", "doc:a#viewer@user:bob"}, nil)
	r2 := write(t, s, []string{"doc:a#viewer@user:carol"}, []string{"doc:a#viewer@user:alice"})
	r3 := write(t, s, nil, []string{"doc:a#viewer@user:bob"})
	if err := p.Prune(ctx, r3+1); !errors.Is(err, rebac.ErrFutureRevision) {
		t.Errorf("Prune after the latest revision: %v, want ErrFutureRevision", err)
	}
	if err := p.Prune(ctx, r2); err != nil {
		t.Fatalf("Prune(%d): %v", r2, err)
	}
	if err := readErr(s, r1); !errors.Is(err, rebac.ErrRevisionExpired) {
		t.Errorf("Read at %d after Prune: %v, want ErrRevisionExpired", r1, err)
	}
	if err := changesErr(s, r1); !errors.Is(err, rebac.ErrRevisionExpired) {
		t.Errorf("Changes after %d after Prune: %v, want ErrRevisionExpired", r1, err)
	}
	f := objRel("doc", "a", "viewer")
	if got, want := readAt(t, s, r2, f), []string{"doc:a#viewer@user:bob", "doc:a#viewer@user:carol"}; !slices.Equal(got, want) {
		t.Errorf("Read at %d after Prune = %q, want %q", r2, got, want)
	}
	if got, want := changes(t, s, r2), []string{fmt.Sprintf("%d delete doc:a#viewer@user:bob", r3)}; !slices.Equal(got, want) {
		t.Errorf("Changes(%d) after Prune = %q, want %q", r2, got, want)
	}
	// Pruning an older revision again is a no-op.
	if err := p.Prune(ctx, r1); err != nil {
		t.Errorf("Prune(%d) after Prune(%d): %v", r1, r2, err)
	}
	if got := readAt(t, s, r3, f); !slices.Equal(got, []string{"doc:a#viewer@user:carol"}) {
		t.Errorf("Read at %d = %q", r3, got)
	}
}

func testCaveats(t *testing.T, s rebac.TupleStore) {
	plain := "doc:a#viewer@user:alice"
	office := `doc:a#viewer@user:alice[office:{"ip":"10.0.0.1"}]`
	home := `doc:a#viewer@user:alice[office:{"ip":"192.168.0.1"}]`
	bare := "doc:a#viewer@user:alice[office]"
	f := objRel("doc", "a", "viewer")

	r1 := write(t, s, []string{office, `doc:a#viewer@user:bob[office:{"cidrs":["10.0.0.0/8","::1/128"],"note":"a#b@c]"}]`}, nil)
	want(t, s, f, office, `doc:a#viewer@user:bob[office:{"cidrs":["10.0.0.0/8","::1/128"],"note":"a#b@c]"}]`)
	// The same caveat again changes nothing; another one replaces it.
	rSame := write(t, s, []string{office}, nil)
	r2 := write(t, s, []string{home}, nil)
	r3 := write(t, s, []string{bare}, nil)
	r4 := write(t, s, []string{plain}, nil)
	for rev, w := range map[rebac.Revision]string{r1: office, rSame: office, r2: home, r3: bare, r4: plain} {
		alice := rebac.Sub("user", "alice")
		if got := readAt(t, s, rev, rebac.Filter{Subject: &alice}); !slices.Equal(got, []string{w}) {
			t.Errorf("Read at %d = %q, want %q", rev, got, w)
		}
	}
	// A delete names the tuple without its caveat.
	r5 := write(t, s, nil, []string{plain})
	r6 := write(t, s, []string{home}, nil)
	r7 := write(t, s, nil, []string{"doc:a#viewer@user:alice"})
	wantChanges := []string{
		fmt.Sprintf("%d delete %s", r2, office), fmt.Sprintf("%d write %s", r2, home),
		fmt.Sprintf("%d delete %s", r3, home), fmt.Sprintf("%d write %s", r3, bare),
		fmt.Sprintf("%d delete %s", r4, bare), fmt.Sprintf("%d write %s", r4, plain),
		fmt.Sprintf("%d delete %s", r5, plain),
		fmt.Sprintf("%d write %s", r6, home),
		fmt.Sprintf("%d delete %s", r7, home),
	}
	if got := changes(t, s, rSame); !slices.Equal(got, wantChanges) {
		t.Errorf("Changes(%d) =\n\t%q\nwant\n\t%q", rSame, got, wantChanges)
	}
}
