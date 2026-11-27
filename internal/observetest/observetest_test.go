package observetest

import (
	"fmt"
	"testing"

	"github.com/tohshi/authent"
)

type failures struct {
	testing.TB
	errors []string
}

func (f *failures) Helper() {}

func (f *failures) Errorf(format string, args ...any) {
	f.errors = append(f.errors, fmt.Sprintf(format, args...))
}

func TestNoSecretsFindsEveryField(t *testing.T) {
	const secret = "s3cr3t"
	for _, e := range []authent.Event{
		{Subject: "x" + secret},
		{Reason: authent.Reason(secret)},
		{Method: authent.Method(secret)},
		{ObjectType: secret},
		{Relation: secret},
		{Decision: authent.Decision(secret)},
	} {
		f := &failures{TB: t}
		NoSecrets(f, []authent.Event{e}, secret)
		if len(f.errors) != 1 {
			t.Errorf("%+v: %d failures, want 1", e, len(f.errors))
		}
	}
	f := &failures{TB: t}
	NoSecrets(f, []authent.Event{{Subject: "alice", Evaluations: 3}}, secret)
	if len(f.errors) != 0 {
		t.Errorf("clean event: %v", f.errors)
	}
}
