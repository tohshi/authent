package rebac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ParamType is the type of a caveat parameter.
type ParamType int

const (
	// ParamString values are strings.
	ParamString ParamType = iota + 1
	// ParamInt values are int64. WithContext also accepts int.
	ParamInt
	// ParamBool values are bools.
	ParamBool
	// ParamTimestamp values are time.Time, stored as RFC 3339 strings.
	ParamTimestamp
	// ParamDuration values are time.Duration, stored as strings such as
	// "1h30m".
	ParamDuration
	// ParamStringList values are []string.
	ParamStringList
)

var paramTypeNames = map[ParamType]string{
	ParamString:     "string",
	ParamInt:        "int",
	ParamBool:       "bool",
	ParamTimestamp:  "timestamp",
	ParamDuration:   "duration",
	ParamStringList: "list<string>",
}

func (p ParamType) String() string {
	if s, ok := paramTypeNames[p]; ok {
		return s
	}
	return "ParamType(" + strconv.Itoa(int(p)) + ")"
}

// Param declares a parameter of a caveat.
type Param struct {
	Name string
	Type ParamType
}

// CaveatFunc decides a caveat. args has a value for every parameter of the
// caveat, of the Go type its ParamType names. It must not keep or modify
// args, and its result must depend only on args.
type CaveatFunc func(args map[string]any) (bool, error)

// CaveatDef defines a caveat. Build one with Caveat.
type CaveatDef struct {
	name   string
	params []Param
	fn     CaveatFunc
}

// Caveat defines a caveat: a condition, decided by fn from typed
// parameters, that a tuple can carry. A relation accepts tuples with the
// caveat through an allowed subject type such as "user with name". The
// parameters a tuple stores take precedence over those a check passes
// with WithContext.
func Caveat(name string, fn CaveatFunc, params ...Param) CaveatDef {
	return CaveatDef{name: name, params: params, fn: fn}
}

func (c *CaveatDef) param(name string) (Param, bool) {
	i := slices.IndexFunc(c.params, func(p Param) bool { return p.Name == name })
	if i < 0 {
		return Param{}, false
	}
	return c.params[i], true
}

func (c *CaveatDef) validate() error {
	if !validName(c.name) {
		return fmt.Errorf("caveat name %q", c.name)
	}
	if c.fn == nil {
		return fmt.Errorf("caveat %s: nil function", c.name)
	}
	seen := map[string]bool{}
	for _, p := range c.params {
		switch {
		case !validName(p.Name):
			return fmt.Errorf("caveat %s: parameter name %q", c.name, p.Name)
		case seen[p.Name]:
			return fmt.Errorf("caveat %s: duplicate parameter %q", c.name, p.Name)
		case paramTypeNames[p.Type] == "":
			return fmt.Errorf("caveat %s: parameter %s: unknown type %v", c.name, p.Name, p.Type)
		}
		seen[p.Name] = true
	}
	return nil
}

// decode parses a stored context into typed values. Every key must be a
// parameter of the caveat.
func (c *CaveatDef) decode(context string) (map[string]any, error) {
	out := map[string]any{}
	if context == "" {
		return out, nil
	}
	raw, err := parseObject(context)
	if err != nil {
		return nil, err
	}
	for k, v := range raw {
		p, ok := c.param(k)
		if !ok {
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
		if out[k], err = decodeValue(p.Type, v); err != nil {
			return nil, fmt.Errorf("parameter %s: %w", k, err)
		}
	}
	return out, nil
}

// canonical returns context in canonical form: compact, with sorted keys
// and values in the form decode reads.
func (c *CaveatDef) canonical(context string) (string, error) {
	vals, err := c.decode(context)
	if err != nil || len(vals) == 0 {
		return "", err
	}
	enc := map[string]any{}
	for k, v := range vals {
		switch v := v.(type) {
		case time.Time:
			enc[k] = v.Format(time.RFC3339Nano)
		case time.Duration:
			enc[k] = v.String()
		default:
			enc[k] = v
		}
	}
	b, err := json.Marshal(enc)
	return string(b), err
}

// parseObject parses a JSON object, rejecting duplicate keys and trailing
// data, so that a context has exactly one meaning.
func parseObject(s string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k := t.(string)
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate key %q", k)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON object")
	}
	return out, nil
}

func decodeValue(typ ParamType, raw json.RawMessage) (any, error) {
	var s string
	switch typ {
	case ParamInt:
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var n json.Number
		if err := dec.Decode(&n); err != nil {
			return nil, err
		}
		return strconv.ParseInt(string(n), 10, 64)
	case ParamBool:
		var b bool
		err := json.Unmarshal(raw, &b)
		return b, err
	case ParamStringList:
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, errors.New("null is not a list")
		}
		var l []string
		err := json.Unmarshal(raw, &l)
		return l, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("null is not a string")
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	switch typ {
	case ParamTimestamp:
		return time.Parse(time.RFC3339Nano, s)
	case ParamDuration:
		return time.ParseDuration(s)
	}
	return s, nil
}

// checkValue returns v, a value passed with WithContext, as the Go type of
// typ.
func checkValue(typ ParamType, v any) (any, error) {
	ok := false
	switch typ {
	case ParamString:
		_, ok = v.(string)
	case ParamInt:
		if i, isInt := v.(int); isInt {
			return int64(i), nil
		}
		_, ok = v.(int64)
	case ParamBool:
		_, ok = v.(bool)
	case ParamTimestamp:
		_, ok = v.(time.Time)
	case ParamDuration:
		_, ok = v.(time.Duration)
	case ParamStringList:
		if l, isList := v.([]string); isList {
			return slices.Clone(l), nil
		}
	}
	if !ok {
		return nil, fmt.Errorf("want %v, got %T", typ, v)
	}
	return v, nil
}

// ErrMissingContext is wrapped by a MissingContextError.
var ErrMissingContext = errors.New("rebac: missing caveat context")

// MissingContextError is the result of a check that depends on caveats
// whose parameters neither the tuples nor WithContext supply. Such a check
// is conditional: it returns false, and may be decided by passing the
// parameters.
type MissingContextError struct {
	// Params are the missing parameters, sorted.
	Params []string
}

func (e *MissingContextError) Error() string {
	return ErrMissingContext.Error() + ": " + strings.Join(e.Params, ", ")
}

func (e *MissingContextError) Unwrap() error { return ErrMissingContext }

// WithContext supplies values for caveat parameters, keyed by parameter
// name, each of the Go type its ParamType names. Values that a tuple
// stores take precedence, so a request cannot override them. A value of
// the wrong type makes checks that need it fail.
func WithContext(values map[string]any) QueryOption {
	return func(c *queryConfig) { c.context = values }
}

// caveat evaluates the caveat a tuple carries.
func (r *run) caveat(c TupleCaveat) result {
	def, ok := r.e.schema.caveats[c.Name]
	if !ok {
		return resUnknown(fmt.Errorf("rebac: unknown caveat %q", c.Name))
	}
	args, err := def.decode(c.Context)
	if err != nil {
		return resUnknown(fmt.Errorf("rebac: caveat %s: stored context: %w", c.Name, err))
	}
	var missing []string
	for _, p := range def.params {
		if _, ok := args[p.Name]; ok {
			continue
		}
		v, ok := r.cfg.context[p.Name]
		if !ok {
			missing = append(missing, p.Name)
			continue
		}
		if args[p.Name], err = checkValue(p.Type, v); err != nil {
			return resUnknown(fmt.Errorf("rebac: caveat %s: parameter %s: %w", c.Name, p.Name, err))
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return resUnknown(&MissingContextError{Params: missing})
	}
	ok, err = callCaveat(def.fn, args)
	if err != nil {
		return resUnknown(fmt.Errorf("rebac: caveat %s: %w", c.Name, err))
	}
	return resBool(ok)
}

func callCaveat(fn CaveatFunc, args map[string]any) (ok bool, err error) {
	defer func() {
		if p := recover(); p != nil {
			ok, err = false, fmt.Errorf("panic: %v", p)
		}
	}()
	return fn(args)
}

// conditional returns the value of a tuple's contribution: the caveat it
// carries, if any, and then the rest.
func (r *run) conditional(c TupleCaveat, rest func() result) result {
	if c.Name == "" {
		return rest()
	}
	cv := r.caveat(c)
	if cv.f.op == opFalse {
		return cv
	}
	return join(opAnd, []result{cv, rest()})
}
