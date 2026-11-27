module github.com/tohshi/authent/integration

go 1.27.4

replace github.com/tohshi/authent => ../

require (
	github.com/jackc/pgx/v5 v5.13.0
	github.com/redis/go-redis/v9 v9.24.0
	github.com/tohshi/authent v0.0.0-20261127045728-eded06a89c9f
	github.com/tohshi/authent/redis v0.0.0-00010101000000-000000000000
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
)

replace github.com/tohshi/authent/redis => ../redis
