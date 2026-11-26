package rebac

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"
	"testing"
)

type countingStore struct {
	*MemoryStore
	mu    sync.Mutex
	reads map[string]int
}

func (c *countingStore) Read(ctx context.Context, rev Revision, f Filter) iter.Seq2[Tuple, error] {
	c.mu.Lock()
	c.reads[f.ObjectType+":"+f.ObjectID+"#"+f.Relation]++
	c.mu.Unlock()
	return c.MemoryStore.Read(ctx, rev, f)
}

func TestCheckBulk(t *testing.T) {
	for _, n := range []int{1, 4} {
		t.Run(fmt.Sprintf("concurrency=%d", n), func(t *testing.T) {
			store := &failingStore{MemoryStore: NewMemoryStore(), failObject: Obj("doc", "broken")}
			e, err := NewEngine(driveSchema(t), store, WithConcurrency(n))
			if err != nil {
				t.Fatal(err)
			}
			write(t, e,
				"doc:d#owner@user:alice",
				"doc:d#banned@user:bob",
				"doc:d#viewer@user:bob",
			)
			items := []CheckItem{
				{Obj("doc", "d"), "viewer", Sub("user", "alice")},
				{Obj("doc", "d"), "viewer", Sub("user", "bob")},
				{Obj("doc", "d"), "viewer", AllOf("user")},
				{Obj("doc", "d"), "nope", Sub("user", "alice")},
				{Obj("doc", "broken"), "viewer", Sub("user", "alice")},
				{Obj("doc", "d"), "editor", Sub("user", "alice")},
			}
			want := []struct {
				allowed bool
				err     error
			}{
				{true, nil},
				{false, nil},
				{false, ErrInvalidTuple},
				{false, ErrUnknownRelation},
				{false, errStore},
				{true, nil},
			}
			got, _ := e.CheckBulk(context.Background(), items)
			if len(got) != len(items) {
				t.Fatalf("%d results for %d items", len(got), len(items))
			}
			for i, w := range want {
				if got[i].Allowed != w.allowed || !errors.Is(got[i].Err, w.err) || (w.err == nil) != (got[i].Err == nil) {
					t.Errorf("item %d %+v = %v, %v; want %v, %v", i, items[i], got[i].Allowed, got[i].Err, w.allowed, w.err)
				}
			}
		})
	}
}

func TestCheckBulkSharesReads(t *testing.T) {
	store := &countingStore{MemoryStore: NewMemoryStore(), reads: map[string]int{}}
	e, err := NewEngine(driveSchema(t), store)
	if err != nil {
		t.Fatal(err)
	}
	write(t, e,
		"doc:d#parent@folder:f",
		"folder:f#viewer@group:eng#member",
		"group:eng#member@user:u3",
	)
	var items []CheckItem
	for i := range 10 {
		items = append(items, CheckItem{Obj("doc", "d"), "viewer", Sub("user", fmt.Sprintf("u%d", i))})
	}
	got, _ := e.CheckBulk(context.Background(), items)
	for i, r := range got {
		if r.Allowed != (i == 3) || r.Err != nil {
			t.Errorf("item %d = %v, %v", i, r.Allowed, r.Err)
		}
	}
	for key, n := range store.reads {
		if n != 1 {
			t.Errorf("%s read %d times, want once", key, n)
		}
	}
	if store.reads["group:eng#member"] != 1 {
		t.Errorf("reads = %v, want group:eng#member among them", store.reads)
	}
}

func TestCheckBulkEvaluationLimitPerItem(t *testing.T) {
	e, _ := NewEngine(driveSchema(t), NewMemoryStore(), WithMaxEvaluations(20))
	for i := range 50 {
		write(t, e, fmt.Sprintf("group:big#member@group:g%d#member", i))
	}
	write(t, e, "group:small#member@user:bob")
	got, _ := e.CheckBulk(context.Background(), []CheckItem{
		{Obj("group", "big"), "member", Sub("user", "bob")},
		{Obj("group", "small"), "member", Sub("user", "bob")},
	})
	if !errors.Is(got[0].Err, ErrTooComplex) || got[0].Allowed {
		t.Errorf("big = %v, %v; want ErrTooComplex", got[0].Allowed, got[0].Err)
	}
	if !got[1].Allowed || got[1].Err != nil {
		t.Errorf("small = %v, %v; want true", got[1].Allowed, got[1].Err)
	}
}
