package rebac

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Revision identifies a state of a TupleStore. Every Write moves the store
// to a higher revision, so a Revision is a consistency token, the
// "zookie" of Zanzibar: a query evaluated at a revision at least as high as
// the one a Write returned sees that write. The empty store is at
// revision 0.
type Revision uint64

func (r Revision) String() string { return strconv.FormatUint(uint64(r), 10) }

// ParseRevision parses the decimal form that Revision.String returns.
func ParseRevision(s string) (Revision, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("rebac: invalid revision %q", s)
	}
	return Revision(n), nil
}

var (
	// ErrFutureRevision is returned when a query asks for a revision that
	// the store has not reached, for example a token from another store or
	// from a primary that a replica has not caught up with.
	ErrFutureRevision = errors.New("rebac: store has not reached the revision")
	// ErrRevisionExpired is returned when a query asks for a revision whose
	// history the store has pruned.
	ErrRevisionExpired = errors.New("rebac: revision has expired")
)

// ChangeOp is the kind of a Change.
type ChangeOp int

const (
	// ChangeWrite adds a tuple.
	ChangeWrite ChangeOp = iota + 1
	// ChangeDelete removes a tuple.
	ChangeDelete
)

func (op ChangeOp) String() string {
	switch op {
	case ChangeWrite:
		return "write"
	case ChangeDelete:
		return "delete"
	}
	return "ChangeOp(" + strconv.Itoa(int(op)) + ")"
}

// Change is a change to the tuples of a store.
type Change struct {
	Revision Revision
	Op       ChangeOp
	Tuple    Tuple
}

// compareChanges orders changes by revision, then deletes before writes,
// then by tuple.
func compareChanges(a, b Change) int {
	switch {
	case a.Revision != b.Revision:
		return compareRevisions(a.Revision, b.Revision)
	case a.Op != b.Op:
		return int(b.Op) - int(a.Op)
	}
	return strings.Compare(a.Tuple.String(), b.Tuple.String())
}

func compareRevisions(a, b Revision) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

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

// TupleStore persists relation tuples and their history. Implementations
// must be safe for concurrent use.
//
// The rebactest package tests implementations against this contract.
type TupleStore interface {
	// Write atomically deletes and then adds tuples, and returns the new
	// revision of the store. Deleting a missing tuple and adding an
	// existing one are no-ops. A Write with no tuples returns the current
	// revision.
	Write(ctx context.Context, writes, deletes []Tuple) (Revision, error)
	// Revision returns the latest revision.
	Revision(ctx context.Context) (Revision, error)
	// Read yields the tuples matching f as they were at revision rev, in
	// any order. It fails with ErrFutureRevision if rev is newer than the
	// latest revision and with ErrRevisionExpired if the history of rev has
	// been pruned.
	//
	// The Engine always sets ObjectType, ObjectID and Relation, so stores
	// should index those. The Engine calls Read again before an earlier
	// sequence is exhausted, so implementations must not hold a resource
	// that the nested call needs, such as the only connection of a pool.
	Read(ctx context.Context, rev Revision, f Filter) iter.Seq2[Tuple, error]
	// Changes yields the changes made after revision after, ordered by
	// revision; within a revision, deletes come before writes and each is
	// ordered by the tuple's string form. A Write that changed nothing
	// leaves no change. Changes fails like Read for a revision that is
	// newer than the latest or has been pruned.
	Changes(ctx context.Context, after Revision) iter.Seq2[Change, error]
}

type objRel struct {
	obj Object
	rel string
}

// netChanges returns the tuples that a Write of writes and deletes leaves
// present (true) or absent (false), deletes applied first.
func netChanges(writes, deletes []Tuple) map[Tuple]bool {
	out := make(map[Tuple]bool, len(writes)+len(deletes))
	for _, t := range deletes {
		out[t] = false
	}
	for _, t := range writes {
		out[t] = true
	}
	return out
}

// MemoryStore is an in-process TupleStore. It keeps every revision until
// Prune discards old ones.
type MemoryStore struct {
	mu      sync.RWMutex
	rev     Revision
	horizon Revision // reads before it fail
	index   map[objRel]map[Subject][]span
	log     []Change
}

// span is when a tuple was present: from created up to, but not including,
// deleted. A deleted of 0 means it still is.
type span struct{ created, deleted Revision }

func (s span) at(rev Revision) bool { return s.created <= rev && (s.deleted == 0 || rev < s.deleted) }

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{index: map[objRel]map[Subject][]span{}}
}

func (m *MemoryStore) Write(_ context.Context, writes, deletes []Tuple) (Revision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(writes) == 0 && len(deletes) == 0 {
		return m.rev, nil
	}
	m.rev++
	var changes []Change
	for t, present := range netChanges(writes, deletes) {
		k := objRel{t.Object, t.Relation}
		spans := m.index[k][t.Subject]
		live := len(spans) > 0 && spans[len(spans)-1].deleted == 0
		switch {
		case present && !live:
			if m.index[k] == nil {
				m.index[k] = map[Subject][]span{}
			}
			m.index[k][t.Subject] = append(spans, span{created: m.rev})
			changes = append(changes, Change{m.rev, ChangeWrite, t})
		case !present && live:
			spans[len(spans)-1].deleted = m.rev
			changes = append(changes, Change{m.rev, ChangeDelete, t})
		}
	}
	slices.SortFunc(changes, compareChanges)
	m.log = append(m.log, changes...)
	return m.rev, nil
}

func (m *MemoryStore) Revision(context.Context) (Revision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rev, nil
}

// checkRevision reports whether the history of rev is available. The
// caller holds m.mu.
func (m *MemoryStore) checkRevision(rev Revision) error {
	switch {
	case rev > m.rev:
		return fmt.Errorf("%w: %d is after %d", ErrFutureRevision, rev, m.rev)
	case rev < m.horizon:
		return fmt.Errorf("%w: %d is before %d", ErrRevisionExpired, rev, m.horizon)
	}
	return nil
}

func (m *MemoryStore) Read(_ context.Context, rev Revision, f Filter) iter.Seq2[Tuple, error] {
	// Snapshot under the lock so that callers may Write while iterating.
	m.mu.RLock()
	err := m.checkRevision(rev)
	var out []Tuple
	add := func(k objRel, subs map[Subject][]span) {
		for s, spans := range subs {
			if t := (Tuple{k.obj, k.rel, s}); visible(spans, rev) {
				if f.matches(t) {
					out = append(out, t)
				}
			}
		}
	}
	switch {
	case err != nil:
	case f.ObjectType != "" && f.ObjectID != "" && f.Relation != "":
		k := objRel{Obj(f.ObjectType, f.ObjectID), f.Relation}
		add(k, m.index[k])
	default:
		for k, subs := range m.index {
			add(k, subs)
		}
	}
	m.mu.RUnlock()

	return func(yield func(Tuple, error) bool) {
		if err != nil {
			yield(Tuple{}, err)
			return
		}
		for _, t := range out {
			if !yield(t, nil) {
				return
			}
		}
	}
}

// visible reports whether a tuple with spans was present at rev. The
// latest span is checked first, since most reads are of recent revisions.
func visible(spans []span, rev Revision) bool {
	for _, s := range slices.Backward(spans) {
		if s.at(rev) {
			return true
		}
	}
	return false
}

func (m *MemoryStore) Changes(_ context.Context, after Revision) iter.Seq2[Change, error] {
	m.mu.RLock()
	err := m.checkRevision(after)
	var out []Change
	if err == nil {
		i, _ := slices.BinarySearchFunc(m.log, after+1, func(c Change, r Revision) int { return compareRevisions(c.Revision, r) })
		out = slices.Clone(m.log[i:])
	}
	m.mu.RUnlock()

	return func(yield func(Change, error) bool) {
		if err != nil {
			yield(Change{}, err)
			return
		}
		for _, c := range out {
			if !yield(c, nil) {
				return
			}
		}
	}
}

// Prune discards the history before revision before: afterwards, reading
// at an earlier revision or asking for changes after one fails with
// ErrRevisionExpired. Queries in progress at such a revision fail too, so
// leave a margin for them.
func (m *MemoryStore) Prune(_ context.Context, before Revision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if before > m.rev {
		return fmt.Errorf("%w: %d is after %d", ErrFutureRevision, before, m.rev)
	}
	if before <= m.horizon {
		return nil
	}
	m.horizon = before
	for k, subs := range m.index {
		for s, spans := range subs {
			spans = slices.DeleteFunc(spans, func(sp span) bool { return sp.deleted != 0 && sp.deleted <= before })
			if len(spans) == 0 {
				delete(subs, s)
			} else {
				subs[s] = spans
			}
		}
		if len(subs) == 0 {
			delete(m.index, k)
		}
	}
	i, _ := slices.BinarySearchFunc(m.log, before+1, func(c Change, r Revision) int { return compareRevisions(c.Revision, r) })
	m.log = slices.Delete(m.log, 0, i)
	return nil
}
