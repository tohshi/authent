package redissession_test

import (
	"testing"

	"github.com/tohshi/authent/redis/redissession"
)

// The Store itself is tested against a real Redis server by the
// conformance suite in the integration module.

func TestNewRejectsNilClient(t *testing.T) {
	if _, err := redissession.New(nil); err == nil {
		t.Fatal("New(nil) succeeded")
	}
}
