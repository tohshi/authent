package rebac

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingStore struct {
	*MemoryStore
	block     Object
	cancelled atomic.Bool
}

func (b *blockingStore) Read(ctx context.Context, f Filter) iter.Seq2[Tuple, error] {
	if f.ObjectType != b.block.Type || f.ObjectID != b.block.ID {
		return b.MemoryStore.Read(ctx, f)
	}
	return func(yield func(Tuple, error) bool) {
		select {
		case <-ctx.Done():
			b.cancelled.Store(true)
			yield(Tuple{}, ctx.Err())
		case <-time.After(10 * time.Second):
			yield(Tuple{}, errors.New("read was not cancelled"))
		}
	}
}

func TestParallelCancelsDecidedSiblings(t *testing.T) {
	store := &blockingStore{MemoryStore: NewMemoryStore(), block: Obj("folder", "slow")}
	e, err := NewEngine(driveSchema(t), store, WithConcurrency(2))
	if err != nil {
		t.Fatal(err)
	}
	write(t, e, "folder:fast#parent@folder:slow", "folder:fast#viewer@user:alice")
	start := time.Now()
	ok, err := e.Check(context.Background(), Obj("folder", "fast"), "viewer", Sub("user", "alice"))
	if !ok || err != nil {
		t.Fatalf("Check = %v, %v; want true", ok, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Check took %v", d)
	}
	if !store.cancelled.Load() {
		t.Fatal("blocked sibling was not cancelled")
	}
}

type delayStore struct {
	*MemoryStore
	slow objRel
}

func (d *delayStore) Read(ctx context.Context, f Filter) iter.Seq2[Tuple, error] {
	if (objRel{Obj(f.ObjectType, f.ObjectID), f.Relation}) == d.slow {
		time.Sleep(100 * time.Millisecond)
	}
	return d.MemoryStore.Read(ctx, f)
}

func TestParallelEvaluationLimitFailsClosed(t *testing.T) {
	s, err := NewSchema(
		Type("user"),
		Type("group", Relation("member", Direct("user"))),
		Type("doc",
			Relation("slow", Direct("user")),
			Relation("viewer", Union(Computed("slow"), Direct("group#member"))),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	store := &delayStore{MemoryStore: NewMemoryStore(), slow: objRel{Obj("doc", "d"), "slow"}}
	e, err := NewEngine(s, store, WithConcurrency(8), WithMaxEvaluations(20))
	if err != nil {
		t.Fatal(err)
	}
	// The slow branch grants after its siblings, evaluated in other
	// goroutines, have used up the shared budget. The check must fail.
	write(t, e, "doc:d#slow@user:bob")
	for i := range 50 {
		write(t, e, fmt.Sprintf("doc:d#viewer@group:g%d#member", i))
	}
	for range 5 {
		ok, err := e.Check(context.Background(), Obj("doc", "d"), "viewer", Sub("user", "bob"))
		if ok || !errors.Is(err, ErrTooComplex) {
			t.Fatalf("Check = %v, %v; want false, ErrTooComplex", ok, err)
		}
	}
}

func TestParallelConcurrentChecks(t *testing.T) {
	e, err := NewEngine(driveSchema(t), NewMemoryStore(), WithConcurrency(4))
	if err != nil {
		t.Fatal(err)
	}
	write(t, e,
		"group:eng#member@group:backend#member",
		"group:backend#member@user:bob",
		"folder:root#viewer@group:eng#member",
		"folder:root#owner@user:carol",
	)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 50 {
				doc := fmt.Sprintf("doc:d%d_%d", i, j)
				write(t, e, doc+"#parent@folder:root", doc+"#banned@user:carol")
				for _, tc := range []struct {
					user string
					want bool
				}{{"bob", true}, {"carol", false}, {"eve", false}} {
					ok, err := e.Check(context.Background(), Obj("doc", doc[4:]), "viewer", Sub("user", tc.user))
					if ok != tc.want || err != nil {
						t.Errorf("Check(%s#viewer@user:%s) = %v, %v", doc, tc.user, ok, err)
						return
					}
				}
			}
		})
	}
	wg.Wait()
}

func TestWithConcurrencyMustBePositive(t *testing.T) {
	if _, err := NewEngine(driveSchema(t), NewMemoryStore(), WithConcurrency(0)); err == nil {
		t.Fatal("WithConcurrency(0) accepted")
	}
}
