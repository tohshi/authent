package rebac

import (
	"errors"
	"testing"

	"github.com/tohshi/authent"
)

func TestSubjectOf(t *testing.T) {
	got, err := SubjectOf(authent.Principal{Subject: "alice", Issuer: "https://idp.example"}, "user")
	if err != nil || got != Sub("user", "alice") {
		t.Fatalf("SubjectOf = %v, %v", got, err)
	}
	for _, p := range []struct{ sub, typ string }{
		{"", "user"},
		{Wildcard, "user"},
		{"a:b", "user"},
		{"a#b", "user"},
		{"a b", "user"},
		{"alice", ""},
		{"alice", "User"},
	} {
		s, err := SubjectOf(authent.Principal{Subject: p.sub}, p.typ)
		if !errors.Is(err, ErrInvalidTuple) || s != (Subject{}) {
			t.Errorf("SubjectOf(%q, %q) = %v, %v, want ErrInvalidTuple", p.sub, p.typ, s, err)
		}
	}
}
