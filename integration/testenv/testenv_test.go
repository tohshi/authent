package testenv

import (
	"bufio"
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
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		t.Fatal(err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || reply != "+PONG\r\n" {
		t.Fatalf("PING = %q, %v", reply, err)
	}
}
