package observe

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

var (
	errGeneral  = fmt.Errorf("general: %w", authent.ErrUnauthenticated)
	errSpecific = fmt.Errorf("%w: specific", errGeneral)
	errOther    = fmt.Errorf("other: %w", authent.ErrUnauthenticated)
)

func init() {
	Register(map[error]authent.Reason{
		errGeneral:  authent.ReasonInvalidToken,
		errSpecific: authent.ReasonExpired,
		errOther:    authent.ReasonReplayed,
	})
}

type uncomparableError []string

func (uncomparableError) Error() string { return "uncomparable" }

func TestReasonOf(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want authent.Reason
	}{
		{nil, ""},
		{errors.New("store down"), ""},
		{uncomparableError{"a"}, ""},
		{authent.ErrUnauthenticated, authent.ReasonUnauthenticated},
		{fmt.Errorf("x: %w", authent.ErrUnauthenticated), authent.ReasonUnauthenticated},
		{errGeneral, authent.ReasonInvalidToken},
		{errSpecific, authent.ReasonExpired},
		{fmt.Errorf("wrapped: %w", errSpecific), authent.ReasonExpired},
		{fmt.Errorf("%w: %w", errOther, errSpecific), authent.ReasonReplayed},
		{fmt.Errorf("%w: %w", uncomparableError{"a"}, errSpecific), authent.ReasonExpired},
	} {
		if got := ReasonOf(tc.err); got != tc.want {
			t.Errorf("ReasonOf(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestResult(t *testing.T) {
	start := time.Now().Add(-time.Second)
	for _, tc := range []struct {
		err  error
		want authent.Event
	}{
		{nil, authent.Event{Outcome: authent.OutcomeSuccess, Subject: "alice"}},
		{errSpecific, authent.Event{Outcome: authent.OutcomeRejected, Reason: authent.ReasonExpired}},
		{errors.New("store down"), authent.Event{Outcome: authent.OutcomeError}},
	} {
		got := Result(authent.KindAuthentication, authent.MethodJWT, start, "alice", tc.err)
		if got.Duration < time.Second {
			t.Errorf("Duration = %v, want at least 1s", got.Duration)
		}
		got.Duration = 0
		tc.want.Kind, tc.want.Method = authent.KindAuthentication, authent.MethodJWT
		if got != tc.want {
			t.Errorf("Result(%v) = %+v, want %+v", tc.err, got, tc.want)
		}
	}
}

func TestNilObserver(t *testing.T) {
	if !Start(nil).IsZero() {
		t.Error("Start(nil) read the clock")
	}
	Done(context.Background(), nil, authent.KindAuthentication, authent.MethodJWT, time.Time{}, "", nil)
	if n := testing.AllocsPerRun(100, func() {
		Done(context.Background(), nil, authent.KindAuthentication, authent.MethodJWT, Start(nil), "", nil)
	}); n != 0 {
		t.Errorf("nil observer allocates %v times", n)
	}
}

func TestEmitRecoversPanics(t *testing.T) {
	called := false
	Emit(context.Background(), authent.ObserverFunc(func(context.Context, authent.Event) {
		called = true
		panic("observer bug")
	}), authent.Event{})
	if !called {
		t.Error("observer not called")
	}
}
