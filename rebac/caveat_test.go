package rebac

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// caveatEngine's caveat flag holds when its bool parameter v is true, and
// office when ip is in one of cidrs. On doc, t is granted to bob, f is not,
// and c is granted only through flag.
func caveatEngine(t *testing.T, tuples ...string) *Engine {
	t.Helper()
	office := func(args map[string]any) (bool, error) {
		ip, err := netip.ParseAddr(args["ip"].(string))
		if err != nil {
			return false, err
		}
		for _, c := range args["cidrs"].([]string) {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return false, err
			}
			if p.Contains(ip) {
				return true, nil
			}
		}
		return false, nil
	}
	s, err := NewSchema(
		Caveat("flag", func(args map[string]any) (bool, error) { return args["v"].(bool), nil }, Param{"v", ParamBool}),
		Caveat("other", func(args map[string]any) (bool, error) { return args["w"].(bool), nil }, Param{"w", ParamBool}),
		Caveat("office", office, Param{"cidrs", ParamStringList}, Param{"ip", ParamString}),
		Caveat("boom", func(map[string]any) (bool, error) { panic("boom") }),
		Caveat("until", func(args map[string]any) (bool, error) {
			return args["now"].(time.Time).Before(args["deadline"].(time.Time)), nil
		}, Param{"now", ParamTimestamp}, Param{"deadline", ParamTimestamp}),
		Type("user"),
		Type("folder", Relation("viewer", Direct("user"))),
		Type("doc",
			Relation("t", Direct("user")),
			Relation("f", Direct("user")),
			Relation("c", Direct("user with flag", "user:* with flag")),
			Relation("d", Direct("user with other")),
			Relation("parent", Direct("folder with flag")),
			Relation("net", Direct("user with office")),
			Relation("panics", Direct("user with boom")),
			Relation("deadline", Direct("user with until")),
			Relation("union_tc", Union(Computed("t"), Computed("c"))),
			Relation("union_fc", Union(Computed("f"), Computed("c"))),
			Relation("union_cd", Union(Computed("c"), Computed("d"))),
			Relation("inter_tc", Intersection(Computed("t"), Computed("c"))),
			Relation("inter_fc", Intersection(Computed("f"), Computed("c"))),
			Relation("excl_tc", Exclusion(Computed("t"), Computed("c"))),
			Relation("excl_ct", Exclusion(Computed("c"), Computed("t"))),
			Relation("excl_cf", Exclusion(Computed("c"), Computed("f"))),
			Relation("excl_fc", Exclusion(Computed("f"), Computed("c"))),
			Relation("inherited", TupleToUserset("parent", "viewer")),
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

func TestCaveatThreeValuedLogic(t *testing.T) {
	e := caveatEngine(t, "doc:d#t@user:bob", "doc:d#c@user:bob[flag]", "doc:d#d@user:bob[other]")
	ctx := context.Background()
	const C = "conditional"
	for _, tc := range []struct {
		rel                 string
		none, vTrue, vFalse any // without context, with v true, with v false
	}{
		{"c", C, true, false},
		{"union_tc", true, true, true},
		{"union_fc", C, true, false},
		{"inter_tc", C, true, false},
		{"inter_fc", false, false, false},
		{"excl_tc", C, false, true},
		{"excl_ct", false, false, false},
		{"excl_cf", C, true, false},
		{"excl_fc", false, false, false},
	} {
		for i, want := range []any{tc.none, tc.vTrue, tc.vFalse} {
			var opts []QueryOption
			if i > 0 {
				opts = append(opts, WithContext(map[string]any{"v": i == 1}))
			}
			ok, err := e.Check(ctx, Obj("doc", "d"), tc.rel, Sub("user", "bob"), opts...)
			var missing *MissingContextError
			switch {
			case want == C:
				if ok || !errors.As(err, &missing) || !slices.Equal(missing.Params, []string{"v"}) || !errors.Is(err, ErrMissingContext) {
					t.Errorf("%s (context %d) = %v, %v; want conditional on v", tc.rel, i, ok, err)
				}
			case ok != want || err != nil:
				t.Errorf("%s (context %d) = %v, %v; want %v", tc.rel, i, ok, err, want)
			}
		}
	}

	// Both operands of a union are conditional: the missing parameters of
	// both are reported.
	_, err := e.Check(ctx, Obj("doc", "d"), "union_cd", Sub("user", "bob"))
	var missing *MissingContextError
	if !errors.As(err, &missing) || !slices.Equal(missing.Params, []string{"v", "w"}) {
		t.Errorf("union_cd: %v; want missing v and w", err)
	}
}

func TestCaveatContext(t *testing.T) {
	e := caveatEngine(t,
		`doc:d#net@user:bob[office:{"cidrs":["10.0.0.0/8"]}]`,
		`doc:d#net@user:eve[office:{"cidrs":["10.0.0.0/8"],"ip":"192.168.0.1"}]`,
		`doc:d#c@user:*[flag:{"v":false}]`,
		"doc:d#panics@user:bob[boom]",
		`doc:d#deadline@user:bob[until:{"deadline":"2030-01-01T00:00:00Z"}]`,
		`doc:d#parent@folder:f[flag]`,
		"folder:f#viewer@user:bob",
	)
	ctx := context.Background()
	at := func(values map[string]any) QueryOption { return WithContext(values) }
	for _, tc := range []struct {
		rel, user string
		opt       QueryOption
		want      bool
		wantErr   error
	}{
		{"net", "bob", at(map[string]any{"ip": "10.1.2.3"}), true, nil},
		{"net", "bob", at(map[string]any{"ip": "192.168.0.1"}), false, nil},
		{"net", "bob", nil, false, ErrMissingContext},
		// Stored values win over the request's.
		{"net", "eve", at(map[string]any{"ip": "10.1.2.3"}), false, nil},
		{"c", "bob", at(map[string]any{"v": true}), false, nil},
		// A value of the wrong type, an error and a panic in the caveat
		// all fail closed, as errors rather than missing context.
		{"net", "bob", at(map[string]any{"ip": 10}), false, errAny},
		{"net", "bob", at(map[string]any{"ip": "not an ip"}), false, errAny},
		{"panics", "bob", nil, false, errAny},
		{"deadline", "bob", at(map[string]any{"now": time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)}), true, nil},
		{"deadline", "bob", at(map[string]any{"now": time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)}), false, nil},
		{"deadline", "bob", at(map[string]any{"now": "2029-01-01"}), false, errAny},
		// The caveat of a tupleset tuple conditions everything reached
		// through it.
		{"inherited", "bob", nil, false, ErrMissingContext},
		{"inherited", "bob", at(map[string]any{"v": true}), true, nil},
		{"inherited", "bob", at(map[string]any{"v": false}), false, nil},
	} {
		var opts []QueryOption
		if tc.opt != nil {
			opts = append(opts, tc.opt)
		}
		ok, err := e.Check(ctx, Obj("doc", "d"), tc.rel, Sub("user", tc.user), opts...)
		switch {
		case tc.wantErr == errAny:
			if ok || err == nil || errors.Is(err, ErrMissingContext) {
				t.Errorf("%s@%s = %v, %v; want an error", tc.rel, tc.user, ok, err)
			}
		case ok != tc.want || !errors.Is(err, tc.wantErr) || (tc.wantErr == nil) != (err == nil):
			t.Errorf("%s@%s = %v, %v; want %v, %v", tc.rel, tc.user, ok, err, tc.want, tc.wantErr)
		}
	}
}

var errAny = errors.New("any error")

func TestCaveatWriteValidation(t *testing.T) {
	e := caveatEngine(t)
	ctx := context.Background()
	for _, tc := range []struct {
		tuple string
		want  error
	}{
		{"doc:d#c@user:bob", ErrSubjectNotAllowed},             // c requires flag
		{"doc:d#t@user:bob[flag]", ErrSubjectNotAllowed},       // t allows no caveat
		{"doc:d#c@user:bob[other]", ErrSubjectNotAllowed},      // wrong caveat
		{`doc:d#c@user:bob[flag:{"x":true}]`, ErrInvalidTuple}, // unknown parameter
		{`doc:d#c@user:bob[flag:{"v":"yes"}]`, ErrInvalidTuple},
		{`doc:d#c@user:bob[flag:{"v":true,"v":false}]`, ErrInvalidTuple},
		{`doc:d#deadline@user:bob[until:{"deadline":"tomorrow"}]`, ErrInvalidTuple},
		{`doc:d#net@user:bob[office:{"cidrs":null}]`, ErrInvalidTuple},
	} {
		tp, err := ParseTuple(tc.tuple)
		if err == nil {
			_, err = e.Write(ctx, []Tuple{tp}, nil)
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("Write(%s) = %v, want %v", tc.tuple, err, tc.want)
		}
	}

	// Contexts are stored in canonical form.
	tp := MustParseTuple(`doc:d#net@user:bob[office:{ "ip" : "10.0.0.1", "cidrs":["10.0.0.0/8"] }]`)
	if _, err := e.Write(ctx, []Tuple{tp}, nil); err != nil {
		t.Fatal(err)
	}
	set, err := e.Expand(ctx, Obj("doc", "d"), "net")
	if err != nil {
		t.Fatal(err)
	}
	want := TupleCaveat{"office", `{"cidrs":["10.0.0.0/8"],"ip":"10.0.0.1"}`}
	if len(set.Children) != 1 || set.Children[0].Caveat != want {
		t.Fatalf("Expand = %+v, want a leaf with caveat %v", set, want)
	}
}

func TestCaveatSchemaValidation(t *testing.T) {
	ok := func(map[string]any) (bool, error) { return true, nil }
	for name, defs := range map[string][]Definition{
		"unknown caveat":     {Type("user"), Type("doc", Relation("v", Direct("user with nope")))},
		"duplicate caveat":   {Caveat("c", ok), Caveat("c", ok)},
		"bad caveat name":    {Caveat("C", ok)},
		"nil function":       {Caveat("c", nil)},
		"duplicate param":    {Caveat("c", ok, Param{"a", ParamInt}, Param{"a", ParamBool})},
		"bad param name":     {Caveat("c", ok, Param{"A", ParamInt})},
		"unknown param type": {Caveat("c", ok, Param{"a", ParamType(99)})},
	} {
		if _, err := NewSchema(defs...); !errors.Is(err, ErrInvalidSchema) {
			t.Errorf("%s: %v, want ErrInvalidSchema", name, err)
		}
	}
}

func TestCaveatLists(t *testing.T) {
	e := caveatEngine(t, "doc:a#c@user:bob[flag]", "doc:b#c@user:bob[flag]", `doc:e#c@user:bob[flag:{"v":true}]`)
	ctx := context.Background()
	got, err := e.ListObjects(ctx, "doc", "c", Sub("user", "bob"))
	if err != nil || !slices.Equal(got, []Object{Obj("doc", "e")}) {
		t.Errorf("ListObjects without context = %v, %v; want only the unconditional grant", got, err)
	}
	got, err = e.ListObjects(ctx, "doc", "c", Sub("user", "bob"), WithContext(map[string]any{"v": true}))
	if err != nil || !slices.Equal(got, []Object{Obj("doc", "a"), Obj("doc", "b"), Obj("doc", "e")}) {
		t.Errorf("ListObjects with context = %v, %v", got, err)
	}
	set, err := e.ListSubjects(ctx, Obj("doc", "a"), "c", "user", WithContext(map[string]any{"v": true}))
	if err != nil || set.All || !slices.Equal(set.Subjects, []Subject{Sub("user", "bob")}) {
		t.Errorf("ListSubjects = %+v, %v", set, err)
	}
}

func TestCaveatCacheIgnoresContextualChecks(t *testing.T) {
	s := caveatEngine(t).schema
	e, _ := NewEngine(s, NewMemoryStore(), WithCheckCache(10))
	write(t, e, "doc:d#c@user:bob[flag]")
	ctx := context.Background()
	for _, v := range []bool{true, false, true} {
		ok, err := e.Check(ctx, Obj("doc", "d"), "c", Sub("user", "bob"), WithContext(map[string]any{"v": v}))
		if ok != v || err != nil {
			t.Fatalf("Check with v=%v = %v, %v", v, ok, err)
		}
	}
}

func TestParseTupleCaveat(t *testing.T) {
	for _, s := range []string{
		"doc:a#viewer@user:bob[flag]",
		`doc:a#viewer@user:bob[office:{"ip":"10.0.0.1"}]`,
		`doc:a#viewer@group:eng#member[office:{"note":"a]b[c@d#e"}]`,
		`doc:a#viewer@user:*[flag:{}]`,
	} {
		tp, err := ParseTuple(s)
		if err != nil || tp.String() != s {
			t.Errorf("ParseTuple(%q) = %v, %v", s, tp, err)
		}
	}
	for _, s := range []string{
		"doc:a#viewer@user:bob[flag", "doc:a#viewer@user:bob[]", "doc:a#viewer@user:bob[Flag]",
		"doc:a#viewer@user:bob[flag:]", "doc:a#viewer@user:bob[flag:[1]]", `doc:a#viewer@user:bob[flag:{"a":1}x]`,
		`doc:a#viewer@user:bob[flag:{"a":1,"a":2}]`, "doc:a[1]#viewer@user:bob", "doc:a#viewer@user:b]ob",
	} {
		if _, err := ParseTuple(s); !errors.Is(err, ErrInvalidTuple) {
			t.Errorf("ParseTuple(%q) = %v, want ErrInvalidTuple", s, err)
		}
	}
}

func FuzzParseTuple(f *testing.F) {
	for _, s := range []string{
		"doc:a#viewer@user:bob", "doc:a#viewer@group:eng#member", "doc:a#viewer@user:*",
		`doc:a#viewer@user:bob[office:{"ip":"10.0.0.1","cidrs":["10.0.0.0/8"]}]`, "doc:a#viewer@user:bob[flag]",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		tp, err := ParseTuple(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidTuple) {
				t.Fatalf("ParseTuple(%q) = %v, not ErrInvalidTuple", s, err)
			}
			return
		}
		again, err := ParseTuple(tp.String())
		if err != nil || again != tp {
			t.Fatalf("ParseTuple(%q) = %#v, which formats as %q and parses as %#v, %v", s, tp, tp.String(), again, err)
		}
	})
}
