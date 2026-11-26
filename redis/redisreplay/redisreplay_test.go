package redisreplay_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/redis/redisreplay"
)

func TestNewRejectsNilClient(t *testing.T) {
	if _, err := redisreplay.New(nil); err == nil {
		t.Fatal("New(nil) succeeded")
	}
}

func TestUnreachableServerFailsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	client := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1, DialTimeout: time.Second})
	defer client.Close()
	c, err := redisreplay.New(client)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := c.Add(context.Background(), "id", time.Minute)
	if fresh || err == nil || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("Add = %v, %v; want false and a store error", fresh, err)
	}
}
