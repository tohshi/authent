#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
consumer_dir=$(mktemp -d)
trap 'rm -rf "$consumer_dir"' EXIT

cd "$consumer_dir"
go mod init example.com/authent-redis-consumer
go mod edit -require=github.com/tohshi/authent/redis@v0.0.0
go mod edit -replace="github.com/tohshi/authent/redis=$repo_root/redis"

cat > consumer_test.go <<'EOF'
package consumer

import (
	"github.com/tohshi/authent/jwt"
	"github.com/tohshi/authent/redis/redisreplay"
	"github.com/tohshi/authent/redis/redissession"
	"github.com/tohshi/authent/session"
)

var _ jwt.ReplayCache = (*redisreplay.Cache)(nil)
var _ session.Store = (*redissession.Store)(nil)
EOF

GOWORK=off go mod tidy
GOWORK=off go test ./...
