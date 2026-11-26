package rebac

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestAtLeast(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	rev, err := e.Write(ctx, []Tuple{MustParseTuple("doc:d#owner@user:alice")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := e.Check(ctx, Obj("doc", "d"), "viewer", Sub("user", "alice"), AtLeast(rev))
	if !ok || err != nil {
		t.Fatalf("Check at least %d = %v, %v", rev, ok, err)
	}

	ahead := AtLeast(rev + 1)
	if ok, err := e.Check(ctx, Obj("doc", "d"), "viewer", Sub("user", "alice"), ahead); ok || !errors.Is(err, ErrFutureRevision) {
		t.Errorf("Check ahead = %v, %v; want ErrFutureRevision", ok, err)
	}
	if _, err := e.CheckBulk(ctx, []CheckItem{{Obj("doc", "d"), "viewer", Sub("user", "alice")}}, ahead); !errors.Is(err, ErrFutureRevision) {
		t.Errorf("CheckBulk ahead: %v; want ErrFutureRevision", err)
	}
	if _, err := e.Expand(ctx, Obj("doc", "d"), "viewer", ahead); !errors.Is(err, ErrFutureRevision) {
		t.Errorf("Expand ahead: %v; want ErrFutureRevision", err)
	}
}

func TestParseRevision(t *testing.T) {
	for _, r := range []Revision{0, 1, 1<<64 - 1} {
		got, err := ParseRevision(r.String())
		if err != nil || got != r {
			t.Errorf("ParseRevision(%q) = %v, %v", r.String(), got, err)
		}
	}
	for _, s := range []string{"", "-1", "+1", "1.0", "0x10", " 1", "18446744073709551616", "abc"} {
		if _, err := ParseRevision(s); err == nil {
			t.Errorf("ParseRevision(%q) succeeded", s)
		}
	}
}

type writeOnReadStore struct {
	*MemoryStore
	at              objRel
	writes, deletes []Tuple
	once            sync.Once
}

func (s *writeOnReadStore) Read(ctx context.Context, rev Revision, f Filter) iter.Seq2[Tuple, error] {
	if (objRel{Obj(f.ObjectType, f.ObjectID), f.Relation}) == s.at {
		s.once.Do(func() {
			if _, err := s.MemoryStore.Write(ctx, s.writes, s.deletes); err != nil {
				panic(err)
			}
		})
	}
	return s.MemoryStore.Read(ctx, rev, f)
}

func TestCheckReadsOneRevision(t *testing.T) {
	// bob is a banned viewer. One write removes him from both. Before and
	// after it he cannot view; a check that read viewer before the write
	// and banned after it would let him.
	both := []Tuple{MustParseTuple("doc:d#viewer@user:bob"), MustParseTuple("doc:d#banned@user:bob")}
	store := &writeOnReadStore{MemoryStore: NewMemoryStore(), at: objRel{Obj("doc", "d"), "viewer"}, deletes: both}
	e, err := NewEngine(driveSchema(t), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Write(context.Background(), both, nil); err != nil {
		t.Fatal(err)
	}
	ok, err := e.Check(context.Background(), Obj("doc", "d"), "viewer", Sub("user", "bob"))
	if ok || err != nil {
		t.Fatalf("Check = %v, %v; want false", ok, err)
	}
}

func TestWatch(t *testing.T) {
	e, err := NewEngine(driveSchema(t), NewMemoryStore(), WithWatchInterval(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start, _ := e.Write(ctx, []Tuple{MustParseTuple("doc:a#owner@user:old")}, nil)

	got := make(chan string)
	done := make(chan error, 1)
	go func() {
		for c, err := range e.Watch(ctx, start) {
			if err != nil {
				done <- err
				return
			}
			got <- fmt.Sprintf("%s %s", c.Op, c.Tuple)
		}
		done <- nil
	}()

	var want []string
	for i := range 3 {
		tp := MustParseTuple(fmt.Sprintf("doc:a#viewer@user:u%d", i))
		if _, err := e.Write(ctx, []Tuple{tp}, []Tuple{MustParseTuple("doc:a#owner@user:old")}); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			want = append(want, "delete doc:a#owner@user:old")
		}
		want = append(want, "write "+tp.String())
	}
	var seen []string
	for len(seen) < len(want) {
		select {
		case s := <-got:
			seen = append(seen, s)
		case err := <-done:
			t.Fatalf("Watch ended early: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatalf("Watch yielded %q, want %q", seen, want)
		}
	}
	if !slices.Equal(seen, want) {
		t.Fatalf("Watch yielded %q, want %q", seen, want)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch ended with %v after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not end after cancel")
	}
}

func TestWatchUnavailableRevision(t *testing.T) {
	store := NewMemoryStore()
	e, _ := NewEngine(driveSchema(t), store)
	ctx := context.Background()
	r1, _ := e.Write(ctx, []Tuple{MustParseTuple("doc:a#owner@user:x")}, nil)
	r2, _ := e.Write(ctx, nil, []Tuple{MustParseTuple("doc:a#owner@user:x")})
	if err := store.Prune(ctx, r2); err != nil {
		t.Fatal(err)
	}
	for after, want := range map[Revision]error{r1: ErrRevisionExpired, r2 + 1: ErrFutureRevision} {
		for _, err := range e.Watch(ctx, after) {
			if !errors.Is(err, want) {
				t.Errorf("Watch(%d): %v, want %v", after, err, want)
			}
			break
		}
	}
}

func TestWatchIdleCursorSurvivesPrune(t *testing.T) {
	store := NewMemoryStore()
	e, _ := NewEngine(driveSchema(t), store, WithWatchInterval(5*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r1, _ := e.Write(ctx, []Tuple{MustParseTuple("doc:a#owner@user:x")}, nil)
	got := make(chan error, 1)
	go func() {
		for c, err := range e.Watch(ctx, r1) {
			if err == nil && c.Tuple.Subject.Object.ID != "y" {
				err = fmt.Errorf("unexpected change %v", c)
			}
			got <- err
			return
		}
	}()
	// Writes that change nothing move the revision but leave no change.
	r2, _ := e.Write(ctx, []Tuple{MustParseTuple("doc:a#owner@user:x")}, nil)
	time.Sleep(50 * time.Millisecond)
	if err := store.Prune(ctx, r2); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	e.Write(ctx, []Tuple{MustParseTuple("doc:a#owner@user:y")}, nil)
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("Watch: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not yield the change")
	}
}
