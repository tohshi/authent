package httpauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/httpauth"
	"github.com/tohshi/authent/internal/observetest"
	"github.com/tohshi/authent/rebac"
)

func TestObserver(t *testing.T) {
	f := newFixture(t)
	rec := &observetest.Recorder{}
	obs := httpauth.WithObserver(rec)
	key, kr, err := f.keys.Create(t.Context(), "svc", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.keys.Revoke(t.Context(), kr.ID); err != nil {
		t.Fatal(err)
	}
	token, s, err := f.sessions.Create(t.Context(), authent.Principal{Subject: "u1", Method: authent.MethodPassword})
	if err != nil {
		t.Fatal(err)
	}
	cookie := func(method string) *http.Request {
		r := httptest.NewRequest(method, "/", nil)
		r.AddCookie(&http.Cookie{Name: "sid", Value: token})
		return r
	}

	bearer := httpauth.Require(httpauth.Any(httpauth.APIKey(f.keys), httpauth.Bearer(f.verifier)), obs)(whoami)
	serve(bearer, withAuth("Bearer "+f.token))
	serve(bearer, withAuth())
	serve(bearer, withAuth("Bearer "+f.token, "Bearer "+f.token))
	serve(bearer, withAuth("Bearer "+key))
	serve(httpauth.Optional(httpauth.Bearer(f.verifier), obs)(whoami), withAuth())
	sessions := httpauth.Require(httpauth.SessionCookie(f.sessions, "sid"), obs)(whoami)
	serve(sessions, cookie(http.MethodGet))
	serve(sessions, cookie(http.MethodPost))
	f.keyStore.err = errors.New("db down")
	serve(bearer, withAuth("Bearer "+key))

	schema, err := rebac.NewSchema(rebac.Type("user"), rebac.Type("doc", rebac.Relation("viewer", rebac.Direct("user"))))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rebac.NewEngine(schema, rebac.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Write(t.Context(), []rebac.Tuple{rebac.MustParseTuple("doc:a#viewer@user:u1")}, nil); err != nil {
		t.Fatal(err)
	}
	doc := func(r *http.Request) (rebac.Object, error) { return rebac.Obj("doc", r.URL.Path[1:]), nil }
	guarded := httpauth.Require(httpauth.SessionCookie(f.sessions, "sid"))(
		httpauth.RequirePermission(engine, "viewer", "user", doc, obs)(whoami))
	for _, path := range []string{"/a", "/b"} {
		r := cookie(http.MethodGet)
		r.URL.Path = path
		serve(guarded, r)
	}

	ev := func(m authent.Method, o authent.Outcome, r authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindHTTPRequest, Method: m, Outcome: o, Reason: r, Subject: sub}
	}
	rec.Expect(t, []authent.Event{
		ev(authent.MethodJWT, authent.OutcomeSuccess, "", "jwt-user"),
		ev("", authent.OutcomeRejected, authent.ReasonNoCredentials, ""),
		ev("", authent.OutcomeRejected, authent.ReasonMalformed, ""),
		ev("", authent.OutcomeRejected, authent.ReasonRevoked, ""),
		ev("", authent.OutcomeSuccess, "", ""),
		ev(authent.MethodSession, authent.OutcomeSuccess, "", "u1"),
		ev("", authent.OutcomeRejected, authent.ReasonCSRF, ""),
		ev("", authent.OutcomeError, "", ""),
		ev(authent.MethodSession, authent.OutcomeSuccess, "", "u1"),
		ev(authent.MethodSession, authent.OutcomeRejected, authent.ReasonForbidden, ""),
	}, f.token, key, token, s.Handle(), s.CSRFToken())
}
