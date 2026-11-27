package rebac

import (
	"context"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
)

const driveText = `type user

type group {
	relation member: [user, group#member]
}

type folder {
	relation owner: [user]
	relation parent: [folder]
	relation viewer: [user, group#member, user:*] or owner or viewer from parent
}

type doc {
	relation parent: [folder]
	relation owner: [user]
	relation editor: [user, group#member] or owner
	relation banned: [user]
	relation cleared: [user]
	relation viewer: ([user, group#member, user:*] or editor or viewer from parent) but not banned
	relation view_secret: viewer and cleared
}
`

func TestParseSchemaMatchesGoAPI(t *testing.T) {
	s, err := ParseSchema("// The schema of rebac_test.go.\n"+strings.ReplaceAll(driveText, "\t", "  "), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.String(); got != driveText {
		t.Errorf("String() of the parsed schema =\n%s\nwant\n%s", got, driveText)
	}
	if got := driveSchema(t).String(); got != driveText {
		t.Errorf("String() of the Go schema =\n%s\nwant\n%s", got, driveText)
	}

	e, err := NewEngine(s, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	write(t, e,
		"group:eng#member@group:backend#member",
		"group:backend#member@user:bob",
		"folder:projects#viewer@group:eng#member",
		"doc:design#parent@folder:projects",
		"doc:design#banned@user:bob",
		"doc:design#owner@user:dave",
		"doc:design#cleared@user:dave",
	)
	runChecks(t, e, []checkCase{
		{"folder:projects", "viewer", "user:bob", true},
		{"doc:design", "viewer", "user:bob", false},
		{"doc:design", "viewer", "user:dave", true},
		{"doc:design", "view_secret", "user:dave", true},
		{"doc:design", "view_secret", "user:bob", false},
	})
}

func TestSchemaStringRoundTrip(t *testing.T) {
	for seed := range 200 {
		w := randomWorld(t, rand.New(rand.NewPCG(uint64(seed), 3)))
		text := w.schema.String()
		s, err := ParseSchema(text, nil)
		if err != nil {
			t.Fatalf("seed %d: ParseSchema(%q): %v", seed, text, err)
		}
		if got := s.String(); got != text {
			t.Fatalf("seed %d: round trip changed\n%s\ninto\n%s", seed, text, got)
		}
	}

	caveats := caveatEngine(t).schema
	funcs := map[string]CaveatFunc{}
	for name, c := range caveats.caveats {
		funcs[name] = c.fn
	}
	text := caveats.String()
	for _, want := range []string{"caveat office(cidrs list<string>, ip string)\n", "relation c: [user with flag, user:* with flag]\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("String() lacks %q:\n%s", want, text)
		}
	}
	s, err := ParseSchema(text, funcs)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.String(); got != text {
		t.Errorf("round trip changed\n%s\ninto\n%s", text, got)
	}
}

func TestParseSchemaErrors(t *testing.T) {
	ok := func(map[string]any) (bool, error) { return true, nil }
	funcs := map[string]CaveatFunc{"c": ok}
	for _, tc := range []struct {
		src       string
		line, col int
		msg       string
	}{
		{"typ user", 1, 1, `expected "type" or "caveat"`},
		{"type User", 1, 6, "expected type name"},
		{"type user\ntype user", 2, 1, `duplicate type "user"`},
		{"type doc {\n  relation v [user]\n}", 2, 14, `expected ":"`},
		{"type user\ntype doc {\n  relation v: [user] or w and x\n}", 3, 27, "mixed operators"},
		{"type user\ntype doc {\n  relation v: [user] but not [user] or [user]\n}", 3, 37, "mixed operators"},
		{"type doc {\n  relation v: []\n}", 2, 16, "empty subject type list"},
		{"type doc {\n  relation v: [user]\n}", 2, 12, `doc#v: allowed subject "user": unknown type`},
		{"type user\ntype doc {\n  relation a: b\n  relation b: a\n}", 3, 12, "depends on itself through Computed"},
		{"type user\ntype doc {\n  relation v: [user]\n  relation v: [user]\n}", 4, 3, `duplicate relation "v"`},
		{"caveat d(x string)", 1, 8, `no function for caveat "d"`},
		{"caveat c(x float)", 1, 12, `unknown parameter type "float"`},
		{"caveat c(x list<int>)", 1, 12, `unknown parameter type "list<int>"`},
		{"caveat c(x string, x int)", 1, 20, `duplicate parameter "x"`},
		{"type user\ntype doc {\n  relation v: [user with nope]\n}", 3, 12, `unknown caveat "nope"`},
		{"type user\ntype doc {\n  relation v: [user\n", 4, 1, `expected ","`},
		{"type doc {\n  relation or: [doc]\n}", 2, 12, "expected relation name"},
	} {
		_, err := ParseSchema(tc.src, funcs)
		var pe *ParseError
		if !errors.As(err, &pe) || !errors.Is(err, ErrInvalidSchema) {
			t.Errorf("ParseSchema(%q) = %v, want a ParseError", tc.src, err)
			continue
		}
		if pe.Line != tc.line || pe.Column != tc.col || !strings.Contains(pe.Msg, tc.msg) {
			t.Errorf("ParseSchema(%q) = %d:%d %q, want %d:%d %q", tc.src, pe.Line, pe.Column, pe.Msg, tc.line, tc.col, tc.msg)
		}
	}
}

// nestedText is a relation v whose operators nest depth deep.
func nestedText(depth int) string {
	e := "a or a"
	for range depth - 1 {
		e = "a or (" + e + ")"
	}
	return "type user\ntype doc {\n  relation a: [user]\n  relation v: " + e + "\n}\n"
}

func TestParseSchemaNestingLimit(t *testing.T) {
	s, err := ParseSchema(nestedText(64), nil)
	if err != nil {
		t.Fatalf("64 deep: %v", err)
	}
	if _, err := ParseSchema(s.String(), nil); err != nil {
		t.Errorf("String() of 64 deep: %v", err)
	}

	for _, tc := range []struct {
		src string
		col int
	}{
		{nestedText(65), 15 + 64*len("a or (") - 1},
		{"type user\ntype doc {\n  relation a: [user]\n  relation v: " + strings.Repeat("(", 1<<20), 15 + 63},
	} {
		_, err := ParseSchema(tc.src, nil)
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Line != 4 || pe.Column != tc.col || !strings.Contains(pe.Msg, "nest more than 64 deep") {
			t.Errorf("ParseSchema(%.60q...) = %v, want a ParseError at 4:%d", tc.src, err, tc.col)
		}
	}
}

func TestNewSchemaNestingLimit(t *testing.T) {
	nested := func(depth int) Rewrite {
		r := Union(Computed("a"), Computed("a"))
		for range depth - 1 {
			r = Union(Computed("a"), r)
		}
		return r
	}
	schema := func(depth int) (*Schema, error) {
		return NewSchema(Type("user"), Type("doc", Relation("a", Direct("user")), Relation("v", nested(depth))))
	}
	s, err := schema(64)
	if err != nil {
		t.Fatalf("64 deep: %v", err)
	}
	if _, err := ParseSchema(s.String(), nil); err != nil {
		t.Errorf("String() of 64 deep: %v", err)
	}
	for _, depth := range []int{65, 100_000} {
		if _, err := schema(depth); !errors.Is(err, ErrInvalidSchema) {
			t.Errorf("%d deep: NewSchema = %v, want ErrInvalidSchema", depth, err)
		}
	}
}

func TestSchemaRejectsKeywordNames(t *testing.T) {
	ok := func(map[string]any) (bool, error) { return true, nil }
	for _, kw := range []string{"type", "relation", "caveat", "or", "and", "but", "not", "from", "with"} {
		for what, defs := range map[string][]Definition{
			"type":      {Type(kw)},
			"relation":  {Type("user"), Type("doc", Relation(kw, Direct("user")))},
			"caveat":    {Caveat(kw, ok)},
			"parameter": {Caveat("c", ok, Param{kw, ParamString})},
		} {
			if _, err := NewSchema(defs...); !errors.Is(err, ErrInvalidSchema) {
				t.Errorf("%s named %q: NewSchema = %v, want ErrInvalidSchema", what, kw, err)
			}
		}
	}
}

func FuzzParseSchema(f *testing.F) {
	f.Add(driveText)
	f.Add("caveat c(a string, b list<string>, t timestamp)\ntype user\ntype doc {\n\trelation v: [user with c] but not (v and w)\n\trelation w: v from p\n\trelation p: [doc]\n}\n")
	f.Add("type a { relation r: [a#r, a:*] and (r or [a]) }")
	ok := func(map[string]any) (bool, error) { return true, nil }
	funcs := map[string]CaveatFunc{"c": ok}
	f.Fuzz(func(t *testing.T, src string) {
		s, err := ParseSchema(src, funcs)
		if err != nil {
			var pe *ParseError
			if !errors.Is(err, ErrInvalidSchema) || !errors.As(err, &pe) || pe.Line < 1 || pe.Column < 1 {
				t.Fatalf("ParseSchema(%q) = %v, want a positioned ParseError", src, err)
			}
			return
		}
		text := s.String()
		again, err := ParseSchema(text, funcs)
		if err != nil {
			t.Fatalf("ParseSchema(String()) of %q: %v\n%s", src, err, text)
		}
		if got := again.String(); got != text {
			t.Fatalf("format is not stable for %q:\n%s\nthen\n%s", src, text, got)
		}
		if _, err := NewEngine(s, NewMemoryStore()); err != nil {
			t.Fatal(err)
		}
		_ = context.Background()
	})
}
