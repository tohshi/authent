package rebac

import (
	"context"
	"iter"
	"sync"
)

// Filter selects tuples. Empty fields match anything. Subject, if non-nil,
// must match exactly (including an empty relation).
type Filter struct {
	ObjectType string
	ObjectID   string
	Relation   string
	Subject    *Subject
}

func (f Filter) matches(t Tuple) bool {
	return (f.ObjectType == "" || f.ObjectType == t.Object.Type) &&
		(f.ObjectID == "" || f.ObjectID == t.Object.ID) &&
		(f.Relation == "" || f.Relation == t.Relation) &&
		(f.Subject == nil || *f.Subject == t.Subject)
}

// TupleStore persists relation tuples. Implementations must be safe for
// concurrent use.
type TupleStore interface {
	// Write atomically deletes and then adds tuples. Deleting a missing
	// tuple and adding an existing one are no-ops.
	Write(ctx context.Context, writes, deletes []Tuple) error
	// Read yields the tuples matching f, in any order. The Engine always
	// sets ObjectType, ObjectID and Relation, so stores should index those.
	// The Engine calls Read again before an earlier sequence is exhausted,
	// so implementations must not hold a resource that the nested call
	// needs, such as the only connection of a pool.
	//
	// The rebactest package tests implementations against this contract.
	Read(ctx context.Context, f Filter) iter.Seq2[Tuple, error]
}

type objRel struct {
	obj Object
	rel string
}

// MemoryStore is an in-process TupleStore.
type MemoryStore struct {
	mu    sync.RWMutex
	index map[objRel]map[Subject]struct{}
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{index: map[objRel]map[Subject]struct{}{}}
}

func (m *MemoryStore) Write(_ context.Context, writes, deletes []Tuple) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range deletes {
		k := objRel{t.Object, t.Relation}
		delete(m.index[k], t.Subject)
		if len(m.index[k]) == 0 {
			delete(m.index, k)
		}
	}
	for _, t := range writes {
		k := objRel{t.Object, t.Relation}
		if m.index[k] == nil {
			m.index[k] = map[Subject]struct{}{}
		}
		m.index[k][t.Subject] = struct{}{}
	}
	return nil
}

func (m *MemoryStore) Read(_ context.Context, f Filter) iter.Seq2[Tuple, error] {
	// Snapshot under the lock so that callers may Write while iterating.
	m.mu.RLock()
	var out []Tuple
	if f.ObjectType != "" && f.ObjectID != "" && f.Relation != "" {
		k := objRel{Obj(f.ObjectType, f.ObjectID), f.Relation}
		for s := range m.index[k] {
			if t := (Tuple{k.obj, k.rel, s}); f.matches(t) {
				out = append(out, t)
			}
		}
	} else {
		for k, subs := range m.index {
			for s := range subs {
				if t := (Tuple{k.obj, k.rel, s}); f.matches(t) {
					out = append(out, t)
				}
			}
		}
	}
	m.mu.RUnlock()

	return func(yield func(Tuple, error) bool) {
		for _, t := range out {
			if !yield(t, nil) {
				return
			}
		}
	}
}
