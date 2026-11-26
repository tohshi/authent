// Package replaytest provides a conformance test suite for jwt.ReplayCache
// implementations.
//
// Use it to test your own cache, or to check sqlreplay.Cache against your
// database and driver:
//
//	func TestCache(t *testing.T) {
//		replaytest.TestReplayCache(t, func(t *testing.T) jwt.ReplayCache {
//			return newEmptyCache(t)
//		})
//	}
package replaytest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tohshi/authent/jwt"
)

// TestReplayCache runs the conformance suite as subtests of t. newCache
// must return a new, empty cache on every call; it may use t.Cleanup to
// release it. The suite uses the real clock and waits about two seconds
// for an entry to expire.
func TestReplayCache(t *testing.T, newCache func(t *testing.T) jwt.ReplayCache) {
	for _, tc := range []struct {
		name string
		fn   func(*testing.T, jwt.ReplayCache)
	}{
		{"SecondAddFails", testSecondAddFails},
		{"IDsAreDistinct", testIDsAreDistinct},
		{"Concurrent", testConcurrent},
		{"Expiry", testExpiry},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.fn(t, newCache(t))
		})
	}
}

func add(t *testing.T, c jwt.ReplayCache, id string, ttl time.Duration) bool {
	t.Helper()
	fresh, err := c.Add(context.Background(), id, ttl)
	if err != nil {
		t.Fatalf("Add(%q): %v", id, err)
	}
	return fresh
}

func testSecondAddFails(t *testing.T, c jwt.ReplayCache) {
	if !add(t, c, "id-1", time.Minute) {
		t.Fatal("first Add reported a replay")
	}
	if add(t, c, "id-1", time.Minute) {
		t.Fatal("second Add accepted a replay")
	}
}

func testIDsAreDistinct(t *testing.T, c jwt.ReplayCache) {
	for _, id := range []string{"id-a", "id-A", "id-a ", "id-b"} {
		if !add(t, c, id, time.Minute) {
			t.Fatalf("Add(%q) collided with another id", id)
		}
	}
}

func testConcurrent(t *testing.T, c jwt.ReplayCache) {
	const n = 32
	var fresh atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			ok, err := c.Add(context.Background(), "id-race", time.Minute)
			if err != nil {
				t.Error(err)
			}
			if ok {
				fresh.Add(1)
			}
		})
	}
	wg.Wait()
	if got := fresh.Load(); got != 1 {
		t.Fatalf("%d of %d concurrent Adds succeeded, want 1", got, n)
	}
}

func testExpiry(t *testing.T, c jwt.ReplayCache) {
	if !add(t, c, "id-expiring", time.Second) {
		t.Fatal("first Add reported a replay")
	}
	if !add(t, c, "id-live", time.Minute) {
		t.Fatal("first Add reported a replay")
	}
	time.Sleep(2 * time.Second)
	if !add(t, c, "id-expiring", time.Minute) {
		t.Fatal("Add after expiry reported a replay")
	}
	if add(t, c, "id-live", time.Minute) {
		t.Fatal("unexpired entry was dropped")
	}
}
