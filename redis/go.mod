module github.com/tohshi/authent/redis

go 1.27.4

replace github.com/tohshi/authent => ../

require (
	github.com/redis/go-redis/v9 v9.24.0
	github.com/tohshi/authent v0.0.0-20261127045728-eded06a89c9f
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)
