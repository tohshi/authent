package sessiontest_test

import (
	"testing"

	"github.com/tohshi/authent/session"
	"github.com/tohshi/authent/session/sessiontest"
)

func TestMemoryStore(t *testing.T) {
	sessiontest.TestStore(t, func(*testing.T) session.Store { return session.NewMemoryStore() })
}
