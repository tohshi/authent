// Package observe builds and emits the authent Events of the sub-packages.
package observe

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"time"

	"github.com/tohshi/authent"
)

var reasons = map[error]authent.Reason{authent.ErrUnauthenticated: authent.ReasonUnauthenticated}

// Register maps sentinel errors to the Reason of errors that wrap them.
// Call it only from init functions.
func Register(m map[error]authent.Reason) { maps.Copy(reasons, m) }

// ReasonOf returns the Reason of the first registered error in err's
// tree, visited in the order of errors.Is, so a specific sentinel wins
// over the general sentinel it wraps.
func ReasonOf(err error) authent.Reason {
	if err == nil {
		return ""
	}
	if reflect.TypeOf(err).Comparable() {
		if r, ok := reasons[err]; ok {
			return r
		}
	}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		return ReasonOf(u.Unwrap())
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			if r := ReasonOf(e); r != "" {
				return r
			}
		}
	}
	return ""
}

// Result returns the Event of a decision that started at start and ended
// with err. subject is kept only on success.
func Result(kind authent.Kind, method authent.Method, start time.Time, subject string, err error) authent.Event {
	e := authent.Event{Kind: kind, Method: method, Duration: time.Since(start)}
	switch {
	case err == nil:
		e.Outcome, e.Subject = authent.OutcomeSuccess, subject
	case errors.Is(err, authent.ErrUnauthenticated):
		e.Outcome, e.Reason = authent.OutcomeRejected, ReasonOf(err)
	default:
		e.Outcome, e.Reason = authent.OutcomeError, ReasonOf(err)
	}
	return e
}

// Start returns the start time of a decision, or the zero time if o is
// nil.
func Start(o authent.Observer) time.Time {
	if o == nil {
		return time.Time{}
	}
	return time.Now()
}

// Emit sends e to o, if o is not nil, and discards a panic in o.
func Emit(ctx context.Context, o authent.Observer, e authent.Event) {
	if o == nil {
		return
	}
	defer func() { _ = recover() }()
	o.Observe(ctx, e)
}

// Done emits the Result of a decision to o, if o is not nil.
func Done(ctx context.Context, o authent.Observer, kind authent.Kind, method authent.Method, start time.Time, subject string, err error) {
	if o == nil {
		return
	}
	Emit(ctx, o, Result(kind, method, start, subject, err))
}
