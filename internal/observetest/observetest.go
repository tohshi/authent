// Package observetest records authent Events in tests.
package observetest

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/tohshi/authent"
)

// Recorder is an authent.Observer that keeps the Events it receives.
type Recorder struct {
	mu     sync.Mutex
	events []authent.Event
}

func (r *Recorder) Observe(_ context.Context, e authent.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// Take returns the recorded Events with Duration cleared and forgets
// them. It fails t if a Duration is
// negative.
func (r *Recorder) Take(t testing.TB) []authent.Event {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.events
	r.events = nil
	for i := range out {
		if out[i].Duration < 0 {
			t.Errorf("event %d: negative duration %v", i, out[i].Duration)
		}
		out[i].Duration = 0
	}
	return out
}

// Expect fails t unless the recorded Events are want and no field of any
// of them contains one of secrets.
func (r *Recorder) Expect(t testing.TB, want []authent.Event, secrets ...string) {
	t.Helper()
	got := r.Take(t)
	if !slices.Equal(got, want) {
		t.Errorf("events:\n got %+v\nwant %+v", got, want)
	}
	NoSecrets(t, got, secrets...)
}

// NoSecrets fails t if any field of any event contains one of secrets.
// It walks the fields by reflection, so fields added to authent.Event are
// checked too.
func NoSecrets(t testing.TB, events []authent.Event, secrets ...string) {
	t.Helper()
	if len(secrets) == 0 {
		t.Fatal("no secrets to look for")
	}
	for _, s := range secrets {
		if s == "" {
			t.Fatal("empty secret")
		}
	}
	for i, e := range events {
		v := reflect.ValueOf(e)
		for j := range v.NumField() {
			text := fmt.Sprint(v.Field(j).Interface())
			for _, s := range secrets {
				if strings.Contains(text, s) {
					t.Errorf("event %d: field %s contains a secret", i, v.Type().Field(j).Name)
				}
			}
		}
	}
}
