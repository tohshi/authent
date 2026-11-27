package httpauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observe"
	"github.com/tohshi/authent/rebac"
)

// RequirePermission returns middleware that lets a request through only if
// its Principal, as the subject subjectType:Subject, has permission on the
// object that object returns for the request. Place it inside Require or
// Optional.
//
// A request without a Principal fails with ErrNoCredentials. A denied
// check, an invalid subject and an invalid object ID fail with
// ErrForbidden. Errors from object and other errors from the check, such
// as store failures, are passed to the error handler as they are.
func RequirePermission(e *rebac.Engine, permission, subjectType string, object func(*http.Request) (rebac.Object, error), opts ...Option) func(http.Handler) http.Handler {
	c := newConfig(nil, opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := observe.Start(c.observer)
			err := allowed(r, e, permission, subjectType, object)
			if c.observer != nil {
				p, _ := authent.FromContext(r.Context())
				c.observe(r, start, p, err)
			}
			if err != nil {
				c.onError(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func allowed(r *http.Request, e *rebac.Engine, permission, subjectType string, object func(*http.Request) (rebac.Object, error)) error {
	p, ok := authent.FromContext(r.Context())
	if !ok {
		return ErrNoCredentials
	}
	sub, err := rebac.SubjectOf(p, subjectType)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrForbidden, err)
	}
	obj, err := object(r)
	if err != nil {
		return err
	}
	ok, err = e.Check(r.Context(), obj, permission, sub)
	switch {
	case errors.Is(err, rebac.ErrInvalidTuple):
		return fmt.Errorf("%w: %w", ErrForbidden, err)
	case err != nil:
		return err
	case !ok:
		return ErrForbidden
	}
	return nil
}
