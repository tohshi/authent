package authent_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

func TestSlogObserver(t *testing.T) {
	var buf bytes.Buffer
	o := authent.SlogObserver(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})))
	ctx := context.Background()
	o.Observe(ctx, authent.Event{Kind: authent.KindAuthentication, Method: authent.MethodPassword, Outcome: authent.OutcomeSuccess, Subject: "u-1", Duration: time.Millisecond})
	o.Observe(ctx, authent.Event{Kind: authent.KindAuthentication, Method: authent.MethodJWT, Outcome: authent.OutcomeRejected, Reason: authent.ReasonExpired})
	o.Observe(ctx, authent.Event{Kind: authent.KindAuthorization, Outcome: authent.OutcomeSuccess, ObjectType: "doc", Relation: "view", Decision: authent.DecisionDenied, Evaluations: 3})
	o.Observe(ctx, authent.Event{Kind: authent.KindAuthorization, Outcome: authent.OutcomeError})

	want := strings.Join([]string{
		"level=INFO msg=authent kind=authentication method=password outcome=success subject=u-1 duration=1ms",
		"level=WARN msg=authent kind=authentication method=jwt outcome=rejected reason=expired duration=0s",
		"level=INFO msg=authent kind=authorization outcome=success object_type=doc relation=view decision=denied duration=0s evaluations=3",
		"level=ERROR msg=authent kind=authorization outcome=error duration=0s evaluations=0",
		"",
	}, "\n")
	if got := buf.String(); got != want {
		t.Errorf("log:\n%s\nwant:\n%s", got, want)
	}
}

func TestSlogObserverSkipsDisabledLevels(t *testing.T) {
	var buf bytes.Buffer
	o := authent.SlogObserver(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	o.Observe(context.Background(), authent.Event{Kind: authent.KindAuthentication, Outcome: authent.OutcomeSuccess})
	if buf.Len() != 0 {
		t.Errorf("logged %q below the handler's level", buf.String())
	}
}
