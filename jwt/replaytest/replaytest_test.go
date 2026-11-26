package replaytest_test

import (
	"testing"

	"github.com/tohshi/authent/jwt"
	"github.com/tohshi/authent/jwt/replaytest"
)

func TestMemoryReplayCache(t *testing.T) {
	replaytest.TestReplayCache(t, func(*testing.T) jwt.ReplayCache { return jwt.NewMemoryReplayCache() })
}
