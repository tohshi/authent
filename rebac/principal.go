package rebac

import (
	"fmt"

	"github.com/tohshi/authent"
)

// SubjectOf returns the subject typ:p.Subject. It fails with an error
// wrapping ErrInvalidTuple if p has no subject or its subject is not a
// valid ID, including the wildcard, so a Principal can never stand for
// every subject of a type.
//
// The Principal's Issuer is not part of the subject. When subjects from
// several issuers are accepted, use a subject type per issuer.
func SubjectOf(p authent.Principal, typ string) (Subject, error) {
	s := Sub(typ, p.Subject)
	if err := validateSubject(s, false); err != nil {
		return Subject{}, fmt.Errorf("rebac: subject of principal: %w", err)
	}
	return s, nil
}
