package testenv

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPostgresReachable(t *testing.T) {
	db := Postgres(t)
	var one int
	if err := db.QueryRowContext(context.Background(), "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("SELECT 1 = %d, %v", one, err)
	}
}

func TestRedisReachable(t *testing.T) {
	conn, err := net.DialTimeout("tcp", RedisAddr(t), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
