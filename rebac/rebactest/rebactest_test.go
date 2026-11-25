package rebactest_test

import (
	"testing"

	"github.com/tohshi/authent/rebac"
	"github.com/tohshi/authent/rebac/rebactest"
)

func TestMemoryStore(t *testing.T) {
	rebactest.TestTupleStore(t, func(*testing.T) rebac.TupleStore { return rebac.NewMemoryStore() })
}
