package rebac

import (
	"errors"
	"fmt"
	"strings"
)

// ParseError is an error in the text of a schema, at a 1-based line and
// byte column. It wraps ErrInvalidSchema.
type ParseError struct {
	Line, Column int
	Msg          string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("rebac: schema:%d:%d: %s", e.Line, e.Column, e.Msg)
}

func (e *ParseError) Unwrap() error { return ErrInvalidSchema }

// ParseSchema parses the text form of a schema and validates it like
// NewSchema. The text maps one to one onto Type, Relation, the rewrites
// and Caveat:
//
//	caveat office(cidr string, ip string)
//
//	type user
//
//	type group {
//		relation member: [user, group#member]
//	}
//
//	type doc {
//		relation parent: [folder]
//		relation owner: [user]
//		relation banned: [user]
//		relation viewer: ([user, user:*, user with office] or owner or viewer from parent) but not banned
//	}
//
// [types] is Direct, a relation name is Computed, "a from b" is
// TupleToUserset(b, a), and "or", "and" and "but not" are Union,
// Intersection and Exclusion. Mixing operators needs parentheses. Caveat
// parameter types are string, int, bool, timestamp, duration and
// list<string>; funcs gives the Go function of every caveat. Comments run
// from // to the end of the line. Expressions nest at most 64 deep,
// counting the top level and each pair of parentheses, so that operators
// nest as deep as NewSchema allows. Names cannot be the keywords type,
// relation, caveat, or, and, but, not, from and with, in the text or in the
// Go API.
//
// Errors are *ParseError values with the position of the problem.
func ParseSchema(src string, funcs map[string]CaveatFunc) (*Schema, error) {
	p := &parser{src: src, line: 1, col: 1, funcs: funcs, at: map[string]token{}}
	p.next()
	defs, err := p.schema()
	if err != nil {
		return nil, err
	}
	s, err := NewSchema(defs...)
	var re *relationError
	if errors.As(err, &re) {
		t := p.at[re.typ+"#"+re.rel]
		return nil, &ParseError{t.line, t.col, re.typ + "#" + re.rel + ": " + re.msg}
	}
	return s, err
}

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokPunct
)

type token struct {
	kind      tokenKind
	text      string
	line, col int
}

type parser struct {
	src       string
	pos       int
	line, col int
	tok       token
	funcs     map[string]CaveatFunc
	at        map[string]token // where each type#relation is defined
	depth     int              // parentheses open around the current expression
}

func (p *parser) errorf(t token, format string, args ...any) error {
	return &ParseError{t.line, t.col, fmt.Sprintf(format, args...)}
}

// next reads the next token into p.tok.
func (p *parser) next() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == '\n':
			p.pos++
			p.line++
			p.col = 1
			continue
		case c == ' ' || c == '\t' || c == '\r':
			p.pos++
			p.col++
			continue
		case strings.HasPrefix(p.src[p.pos:], "//"):
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		break
	}
	t := token{line: p.line, col: p.col}
	if p.pos == len(p.src) {
		p.tok = t
		return
	}
	end := p.pos + 1
	if isIdentByte(p.src[p.pos]) {
		for end < len(p.src) && isIdentByte(p.src[end]) {
			end++
		}
		t.kind = tokIdent
	} else {
		t.kind = tokPunct
	}
	t.text = p.src[p.pos:end]
	p.col += end - p.pos
	p.pos = end
	p.tok = t
}

func isIdentByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_'
}

func (p *parser) is(text string) bool { return p.tok.text == text && p.tok.kind != tokEOF }

func (p *parser) expect(text string) error {
	if !p.is(text) {
		return p.errorf(p.tok, "expected %q, found %s", text, describe(p.tok))
	}
	p.next()
	return nil
}

func describe(t token) string {
	if t.kind == tokEOF {
		return "end of input"
	}
	return fmt.Sprintf("%q", t.text)
}

// name reads a type, relation, caveat or parameter name.
func (p *parser) name(what string) (string, token, error) {
	t := p.tok
	if t.kind != tokIdent || !validDefName(t.text) {
		return "", t, p.errorf(t, "expected %s name, found %s", what, describe(t))
	}
	p.next()
	return t.text, t, nil
}

func (p *parser) schema() ([]Definition, error) {
	var defs []Definition
	types := map[string]bool{}
	caveats := map[string]bool{}
	for p.tok.kind != tokEOF {
		start := p.tok
		switch {
		case p.is("type"):
			p.next()
			t, err := p.typeDef(start)
			if err != nil {
				return nil, err
			}
			if types[t.name] {
				return nil, p.errorf(start, "duplicate type %q", t.name)
			}
			types[t.name] = true
			defs = append(defs, t)
		case p.is("caveat"):
			p.next()
			c, err := p.caveatDef()
			if err != nil {
				return nil, err
			}
			if caveats[c.name] {
				return nil, p.errorf(start, "duplicate caveat %q", c.name)
			}
			caveats[c.name] = true
			defs = append(defs, c)
		default:
			return nil, p.errorf(start, "expected \"type\" or \"caveat\", found %s", describe(start))
		}
	}
	return defs, nil
}

func (p *parser) typeDef(start token) (TypeDef, error) {
	name, _, err := p.name("type")
	if err != nil {
		return TypeDef{}, err
	}
	t := TypeDef{name: name}
	if !p.is("{") {
		return t, nil
	}
	p.next()
	seen := map[string]bool{}
	for !p.is("}") {
		at := p.tok
		if err := p.expect("relation"); err != nil {
			return TypeDef{}, err
		}
		rel, relTok, err := p.name("relation")
		if err != nil {
			return TypeDef{}, err
		}
		if seen[rel] {
			return TypeDef{}, p.errorf(at, "duplicate relation %q", rel)
		}
		seen[rel] = true
		p.at[name+"#"+rel] = relTok
		if err := p.expect(":"); err != nil {
			return TypeDef{}, err
		}
		rw, err := p.expr()
		if err != nil {
			return TypeDef{}, err
		}
		t.relations = append(t.relations, Relation(rel, rw))
	}
	p.next()
	return t, nil
}

var paramTypes = func() map[string]ParamType {
	m := map[string]ParamType{}
	for t, name := range paramTypeNames {
		m[name] = t
	}
	return m
}()

func (p *parser) caveatDef() (CaveatDef, error) {
	name, nameTok, err := p.name("caveat")
	if err != nil {
		return CaveatDef{}, err
	}
	fn, ok := p.funcs[name]
	if !ok || fn == nil {
		return CaveatDef{}, p.errorf(nameTok, "no function for caveat %q", name)
	}
	if err := p.expect("("); err != nil {
		return CaveatDef{}, err
	}
	var params []Param
	seen := map[string]bool{}
	for !p.is(")") {
		if len(params) > 0 {
			if err := p.expect(","); err != nil {
				return CaveatDef{}, err
			}
		}
		pname, pt, err := p.name("parameter")
		if err != nil {
			return CaveatDef{}, err
		}
		if seen[pname] {
			return CaveatDef{}, p.errorf(pt, "duplicate parameter %q", pname)
		}
		seen[pname] = true
		typTok := p.tok
		typ := p.tok.text
		p.next()
		if typ == "list" {
			if err := p.expect("<"); err != nil {
				return CaveatDef{}, err
			}
			elem := p.tok.text
			p.next()
			if err := p.expect(">"); err != nil {
				return CaveatDef{}, err
			}
			typ = "list<" + elem + ">"
		}
		pty, ok := paramTypes[typ]
		if !ok || typTok.kind != tokIdent {
			return CaveatDef{}, p.errorf(typTok, "unknown parameter type %q", typ)
		}
		params = append(params, Param{pname, pty})
	}
	p.next()
	return Caveat(name, fn, params...), nil
}

// expr reads terms joined by one kind of operator.
func (p *parser) expr() (Rewrite, error) {
	first, err := p.term()
	if err != nil {
		return nil, err
	}
	switch {
	case p.is("but"):
		p.next()
		if err := p.expect("not"); err != nil {
			return nil, err
		}
		sub, err := p.term()
		if err != nil {
			return nil, err
		}
		if p.is("or") || p.is("and") || p.is("but") {
			return nil, p.errorf(p.tok, "mixed operators need parentheses")
		}
		return Exclusion(first, sub), nil
	case p.is("or"), p.is("and"):
		op := p.tok.text
		children := []Rewrite{first}
		for p.is(op) {
			p.next()
			t, err := p.term()
			if err != nil {
				return nil, err
			}
			children = append(children, t)
		}
		if p.is("or") || p.is("and") || p.is("but") {
			return nil, p.errorf(p.tok, "mixed operators need parentheses")
		}
		if op == "or" {
			return Union(children...), nil
		}
		return Intersection(children...), nil
	}
	return first, nil
}

func (p *parser) term() (Rewrite, error) {
	switch {
	case p.is("("):
		if p.depth+1 == maxRewriteDepth {
			return nil, p.errorf(p.tok, "expressions nest more than %d deep", maxRewriteDepth)
		}
		p.next()
		p.depth++
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		p.depth--
		return e, p.expect(")")
	case p.is("["):
		p.next()
		var allowed []string
		for !p.is("]") {
			if len(allowed) > 0 {
				if err := p.expect(","); err != nil {
					return nil, err
				}
			}
			spec, err := p.subjectSpec()
			if err != nil {
				return nil, err
			}
			allowed = append(allowed, spec)
		}
		at := p.tok
		p.next()
		if len(allowed) == 0 {
			return nil, p.errorf(at, "empty subject type list")
		}
		return Direct(allowed...), nil
	}
	rel, _, err := p.name("relation")
	if err != nil {
		return nil, err
	}
	if !p.is("from") {
		return Computed(rel), nil
	}
	p.next()
	tupleset, _, err := p.name("relation")
	if err != nil {
		return nil, err
	}
	return TupleToUserset(tupleset, rel), nil
}

func (p *parser) subjectSpec() (string, error) {
	spec, _, err := p.name("type")
	if err != nil {
		return "", err
	}
	switch {
	case p.is(":"):
		p.next()
		if err := p.expect("*"); err != nil {
			return "", err
		}
		spec += ":*"
	case p.is("#"):
		p.next()
		rel, _, err := p.name("relation")
		if err != nil {
			return "", err
		}
		spec += "#" + rel
	}
	if p.is("with") {
		p.next()
		c, _, err := p.name("caveat")
		if err != nil {
			return "", err
		}
		spec += " with " + c
	}
	return spec, nil
}

// String returns the text form of s, which ParseSchema reads back into the
// same schema given the caveat functions. A Union or Intersection with a
// single operand is written as that operand.
func (s *Schema) String() string {
	var b strings.Builder
	for i, d := range s.defs {
		if i > 0 {
			b.WriteString("\n")
		}
		switch d := d.(type) {
		case CaveatDef:
			var params []string
			for _, p := range d.params {
				params = append(params, p.Name+" "+p.Type.String())
			}
			fmt.Fprintf(&b, "caveat %s(%s)\n", d.name, strings.Join(params, ", "))
		case TypeDef:
			if len(d.relations) == 0 {
				fmt.Fprintf(&b, "type %s\n", d.name)
				continue
			}
			fmt.Fprintf(&b, "type %s {\n", d.name)
			for _, r := range d.relations {
				fmt.Fprintf(&b, "\trelation %s: %s\n", r.name, formatRewrite(r.rewrite, false))
			}
			b.WriteString("}\n")
		}
	}
	return b.String()
}

// formatRewrite writes r, in parentheses if nested is set and r is an
// operator.
func formatRewrite(r Rewrite, nested bool) string {
	var op string
	var children []Rewrite
	switch r := r.(type) {
	case direct:
		return "[" + strings.Join(r.allowed, ", ") + "]"
	case computed:
		return r.relation
	case tupleToUserset:
		return r.computed + " from " + r.tupleset
	case union:
		op, children = " or ", r.children
	case intersection:
		op, children = " and ", r.children
	case exclusion:
		op, children = " but not ", []Rewrite{r.base, r.subtract}
	}
	if len(children) == 1 {
		return formatRewrite(children[0], nested)
	}
	parts := make([]string, len(children))
	for i, c := range children {
		parts[i] = formatRewrite(c, true)
	}
	s := strings.Join(parts, op)
	if nested {
		s = "(" + s + ")"
	}
	return s
}
