package httpauth_test

import (
	"context"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/httpauth"
	"github.com/tohshi/authent/rebac"
)

type brokenStore struct{ *rebac.MemoryStore }

func (brokenStore) Read(context.Context, rebac.Revision, rebac.Filter) iter.Seq2[rebac.Tuple, error] {
	return func(yield func(rebac.Tuple, error) bool) { yield(rebac.Tuple{}, errors.New("db down")) }
}

func TestRequirePermission(t *testing.T) {
	schema, err := rebac.NewSchema(
		rebac.Type("user"),
		rebac.Type("doc", rebac.Relation("viewer", rebac.Direct("user", "user:*"))),
	)
	if err != nil {
		t.Fatal(err)
	}
	newEngine := func(store rebac.TupleStore) *rebac.Engine {
		e, err := rebac.NewEngine(schema, store)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	engine := newEngine(rebac.NewMemoryStore())
	if _, err := engine.Write(t.Context(), []rebac.Tuple{
		rebac.MustParseTuple("doc:secret#viewer@user:alice"),
		rebac.MustParseTuple("doc:public#viewer@user:*"),
	}, nil); err != nil {
		t.Fatal(err)
	}
	broken := newEngine(brokenStore{rebac.NewMemoryStore()})

	docFromPath := func(r *http.Request) (rebac.Object, error) {
		return rebac.Obj("doc", strings.TrimPrefix(r.URL.Path, "/docs/")), nil
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})
	guard := func(e *rebac.Engine, permission string) http.Handler {
		return httpauth.RequirePermission(e, permission, "user", docFromPath)(ok)
	}
	as := func(subject, path string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if subject != "" {
			r = r.WithContext(authent.NewContext(r.Context(), authent.Principal{Subject: subject}))
		}
		return r
	}

	cases := []struct {
		name string
		h    http.Handler
		req  *http.Request
		code int
	}{
		{"granted", guard(engine, "viewer"), as("alice", "/docs/secret"), 200},
		{"granted through wildcard", guard(engine, "viewer"), as("bob", "/docs/public"), 200},
		{"denied", guard(engine, "viewer"), as("bob", "/docs/secret"), 403},
		{"wildcard principal", guard(engine, "viewer"), as("*", "/docs/secret"), 403},
		{"invalid principal subject", guard(engine, "viewer"), as("user:alice", "/docs/secret"), 403},
		{"invalid object id", guard(engine, "viewer"), as("alice", "/docs/a:b"), 403},
		{"no principal", guard(engine, "viewer"), as("", "/docs/public"), 401},
		{"unknown permission", guard(engine, "editor"), as("alice", "/docs/secret"), 500},
		{"store failure", guard(broken, "viewer"), as("alice", "/docs/secret"), 500},
	}
	for _, c := range cases {
		if w := serve(c.h, c.req); w.Code != c.code {
			t.Errorf("%s: got %d, want %d", c.name, w.Code, c.code)
		}
	}

	notFound := errors.New("no such route")
	var got error
	h := httpauth.RequirePermission(engine, "viewer", "user",
		func(*http.Request) (rebac.Object, error) { return rebac.Object{}, notFound },
		httpauth.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
			got = err
			w.WriteHeader(http.StatusNotFound)
		}))(ok)
	if w := serve(h, as("alice", "/x")); w.Code != 404 || !errors.Is(got, notFound) {
		t.Fatalf("object error: got %d, err %v", w.Code, got)
	}
}
