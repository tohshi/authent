package rebac

import (
	"context"
	"testing"
)

func TestCheckCache(t *testing.T) {
	store := &countingStore{MemoryStore: NewMemoryStore(), reads: map[string]int{}}
	e, err := NewEngine(driveSchema(t), store, WithCheckCache(2))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	reads := func() int {
		store.mu.Lock()
		defer store.mu.Unlock()
		n := 0
		for _, c := range store.reads {
			n += c
		}
		return n
	}
	check := func(user string, want, cachedWant bool, opts ...QueryOption) {
		t.Helper()
		before := reads()
		ok, err := e.Check(ctx, Obj("doc", "d"), "viewer", Sub("user", user), opts...)
		if ok != want || err != nil {
			t.Fatalf("Check(%s) = %v, %v; want %v", user, ok, err, want)
		}
		if cached := reads() == before; cached != cachedWant {
			t.Fatalf("Check(%s) cached = %v, want %v", user, cached, cachedWant)
		}
	}

	r1, _ := e.Write(ctx, []Tuple{MustParseTuple("doc:d#owner@user:alice")}, nil)
	check("alice", true, false)
	check("alice", true, true)
	check("alice", true, true, AtLeast(r1))

	// A revoke takes effect at once, whatever token the caller passes.
	r2, _ := e.Write(ctx, nil, []Tuple{MustParseTuple("doc:d#owner@user:alice")})
	check("alice", false, false, AtLeast(r1))
	check("alice", false, true, AtLeast(0))
	check("alice", false, true)
	e.Write(ctx, []Tuple{MustParseTuple("doc:other#owner@user:x")}, nil)
	check("alice", false, false, AtLeast(r2))

	check("bob", false, false)
	check("carol", false, false)
	check("bob", false, true)
	check("alice", false, false)

	items := []CheckItem{{Obj("doc", "d"), "viewer", Sub("user", "bob")}, {Obj("doc", "d"), "viewer", Sub("user", "alice")}}
	before := reads()
	got, err := e.CheckBulk(ctx, items)
	if err != nil || got[0].Allowed || got[1].Allowed || reads() != before {
		t.Fatalf("CheckBulk = %v, %v with %d reads; want cached denials", got, err, reads()-before)
	}
}

func TestCheckCacheSkipsErrors(t *testing.T) {
	store := &failingStore{MemoryStore: NewMemoryStore(), failObject: Obj("doc", "d")}
	e, _ := NewEngine(driveSchema(t), store, WithCheckCache(10))
	ctx := context.Background()
	for range 2 {
		if ok, err := e.Check(ctx, Obj("doc", "d"), "viewer", Sub("user", "alice")); ok || err == nil {
			t.Fatalf("Check = %v, %v; want an error", ok, err)
		}
	}
	store.failObject = Obj("doc", "other")
	e.Write(ctx, []Tuple{MustParseTuple("doc:d#owner@user:alice")}, nil)
	if ok, err := e.Check(ctx, Obj("doc", "d"), "viewer", Sub("user", "alice")); !ok || err != nil {
		t.Fatalf("Check after recovery = %v, %v", ok, err)
	}
}
