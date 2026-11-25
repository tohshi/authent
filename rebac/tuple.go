// Package rebac implements Zanzibar-style relationship-based access control.
//
// Access is derived from relation tuples such as
//
//	doc:readme#viewer@user:alice        alice is a viewer of doc:readme
//	doc:readme#viewer@group:eng#member  members of group:eng are viewers
//	doc:readme#parent@folder:root       doc:readme is inside folder:root
//	doc:readme#viewer@user:*            every user is a viewer
//
// and a Schema that defines, per object type, how each relation is computed
// from tuples and from other relations (see Direct, Computed,
// TupleToUserset, Union, Intersection and Exclusion).
package rebac

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Wildcard is the object ID that matches every object of a type when used
// as a subject, as in "user:*".
const Wildcard = "*"

// Object identifies a resource, such as doc:readme.
type Object struct {
	Type string
	ID   string
}

// Obj returns the Object typ:id.
func Obj(typ, id string) Object { return Object{Type: typ, ID: id} }

func (o Object) String() string { return o.Type + ":" + o.ID }

// Subject is who a relation is granted to: either an object (Relation is
// empty), such as user:alice, or a userset, such as group:eng#member
// meaning "everyone with relation member to group:eng".
type Subject struct {
	Object   Object
	Relation string
}

// Sub returns the subject typ:id.
func Sub(typ, id string) Subject { return Subject{Object: Obj(typ, id)} }

// Userset returns the subject typ:id#relation.
func Userset(typ, id, relation string) Subject {
	return Subject{Object: Obj(typ, id), Relation: relation}
}

// AllOf returns the wildcard subject typ:*.
func AllOf(typ string) Subject { return Sub(typ, Wildcard) }

func (s Subject) String() string {
	if s.Relation == "" {
		return s.Object.String()
	}
	return s.Object.String() + "#" + s.Relation
}

func (s Subject) isWildcard() bool { return s.Object.ID == Wildcard }

// Tuple states that Subject has Relation to Object.
type Tuple struct {
	Object   Object
	Relation string
	Subject  Subject
}

func (t Tuple) String() string {
	return t.Object.String() + "#" + t.Relation + "@" + t.Subject.String()
}

// ErrInvalidTuple is returned for syntactically invalid tuples, objects and
// subjects.
var ErrInvalidTuple = errors.New("rebac: invalid tuple")

// ParseTuple parses "type:id#relation@type:id[#relation]".
func ParseTuple(s string) (Tuple, error) {
	objRel, sub, ok := strings.Cut(s, "@")
	if !ok {
		return Tuple{}, fmt.Errorf("%w: %q: missing '@'", ErrInvalidTuple, s)
	}
	obj, rel, ok := strings.Cut(objRel, "#")
	if !ok {
		return Tuple{}, fmt.Errorf("%w: %q: missing '#'", ErrInvalidTuple, s)
	}
	o, err := ParseObject(obj)
	if err != nil {
		return Tuple{}, err
	}
	subject, err := ParseSubject(sub)
	if err != nil {
		return Tuple{}, err
	}
	t := Tuple{Object: o, Relation: rel, Subject: subject}
	return t, t.validate()
}

// MustParseTuple is like ParseTuple but panics on error.
func MustParseTuple(s string) Tuple {
	t, err := ParseTuple(s)
	if err != nil {
		panic(err)
	}
	return t
}

// ParseObject parses "type:id".
func ParseObject(s string) (Object, error) {
	typ, id, ok := strings.Cut(s, ":")
	if !ok {
		return Object{}, fmt.Errorf("%w: object %q: missing ':'", ErrInvalidTuple, s)
	}
	o := Obj(typ, id)
	return o, validateObject(o, false)
}

// ParseSubject parses "type:id" or "type:id#relation".
func ParseSubject(s string) (Subject, error) {
	obj, rel, hasRel := strings.Cut(s, "#")
	if hasRel && rel == "" {
		return Subject{}, fmt.Errorf("%w: subject %q: empty relation", ErrInvalidTuple, s)
	}
	typ, id, ok := strings.Cut(obj, ":")
	if !ok {
		return Subject{}, fmt.Errorf("%w: subject %q: missing ':'", ErrInvalidTuple, s)
	}
	sub := Subject{Object: Obj(typ, id), Relation: rel}
	return sub, validateSubject(sub, true)
}

var errWildcard = fmt.Errorf("%w: wildcard not allowed here", ErrInvalidTuple)

const maxIDLength = 256

// validName reports whether s is a valid type or relation name.
func validName(s string) bool {
	if len(s) == 0 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func validateObject(o Object, allowWildcard bool) error {
	if !validName(o.Type) {
		return fmt.Errorf("%w: type %q", ErrInvalidTuple, o.Type)
	}
	if o.ID == Wildcard {
		if !allowWildcard {
			return errWildcard
		}
		return nil
	}
	if len(o.ID) == 0 || len(o.ID) > maxIDLength {
		return fmt.Errorf("%w: id length %d", ErrInvalidTuple, len(o.ID))
	}
	for _, r := range o.ID {
		if r == ':' || r == '#' || r == '@' || r == '*' || unicode.IsSpace(r) || unicode.IsControl(r) || r == unicode.ReplacementChar {
			return fmt.Errorf("%w: id %q contains %q", ErrInvalidTuple, o.ID, r)
		}
	}
	return nil
}

func validateSubject(s Subject, allowWildcard bool) error {
	if err := validateObject(s.Object, allowWildcard); err != nil {
		return err
	}
	if s.Relation != "" {
		if s.isWildcard() {
			return fmt.Errorf("%w: wildcard subject cannot have a relation", ErrInvalidTuple)
		}
		if !validName(s.Relation) {
			return fmt.Errorf("%w: relation %q", ErrInvalidTuple, s.Relation)
		}
	}
	return nil
}

func (t Tuple) validate() error {
	if err := validateObject(t.Object, false); err != nil {
		return err
	}
	if !validName(t.Relation) {
		return fmt.Errorf("%w: relation %q", ErrInvalidTuple, t.Relation)
	}
	return validateSubject(t.Subject, true)
}
