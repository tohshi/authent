// Package redissession provides a session.Store backed by Redis.
//
// It lives in the github.com/tohshi/authent/redis module, so that the core
// module keeps no dependencies beyond the standard library and
// golang.org/x.
package redissession

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/tohshi/authent/session"
)

// DefaultPrefix is the key prefix a Store uses unless WithPrefix is given.
const DefaultPrefix = "authent:session:"

// Store is a session.Store backed by Redis.
//
// Each session is a hash under prefix+"k:"+key that expires with the
// session. Each subject has a sorted set under prefix+"s:"+subject holding
// its keys, scored by expiry; the set expires with its last session, and
// entries of deleted sessions are removed with them, and entries of
// expired sessions are pruned as sessions are saved.
// Lua scripts make compare-and-swap and DeleteSubject atomic.
//
// Expiry is set as a TTL relative to the application's clock, so clock
// differences between the application and Redis do not shorten sessions.
// Redis Cluster is not supported: the scripts touch keys of several slots.
type Store struct {
	client *redis.Client
	prefix string
	now    func() time.Time
}

// Option configures a Store.
type Option func(*Store)

// WithPrefix sets the prefix of every key the Store writes. The default is
// DefaultPrefix.
func WithPrefix(prefix string) Option { return func(s *Store) { s.prefix = prefix } }

// New returns a Store that keeps sessions in the Redis server of client.
func New(client *redis.Client, opts ...Option) (*Store, error) {
	if client == nil {
		return nil, errors.New("redissession: nil *redis.Client")
	}
	s := &Store{client: client, prefix: DefaultPrefix, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func (s *Store) recordKey(key string) string      { return s.prefix + "k:" + key }
func (s *Store) subjectKey(subject string) string { return s.prefix + "s:" + subject }

// saveScript stores a session if its key holds the expected version
// (ARGV[1], "0" for none). A TTL of zero deletes the session instead, since
// it has already expired.
var saveScript = redis.NewScript(`
if (redis.call('HGET', KEYS[1], 'v') or '0') ~= ARGV[1] then return 0 end
local ttl = tonumber(ARGV[6])
if ttl <= 0 then
	redis.call('DEL', KEYS[1])
	redis.call('ZREM', KEYS[2], ARGV[7])
	return 1
end
redis.call('HSET', KEYS[1], 's', ARGV[3], 'v', ARGV[2], 'e', ARGV[4], 'd', ARGV[5])
redis.call('PEXPIRE', KEYS[1], ttl)
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
redis.call('ZADD', KEYS[2], now + ttl, ARGV[7])
local last = redis.call('ZRANGE', KEYS[2], -1, -1, 'WITHSCORES')
redis.call('PEXPIREAT', KEYS[2], last[2])
return 1
`)

// deleteScript deletes a session if its version is ARGV[1], or whatever
// its version if ARGV[1] is "0", and removes it from its subject's index.
// ARGV[2] is the prefix of index keys and ARGV[3] the session key.
var deleteScript = redis.NewScript(`
local fields = redis.call('HMGET', KEYS[1], 's', 'v')
if ARGV[1] ~= '0' and fields[2] ~= ARGV[1] then return 0 end
redis.call('DEL', KEYS[1])
if fields[1] then redis.call('ZREM', ARGV[2] .. fields[1], ARGV[3]) end
return 1
`)

// deleteSubjectScript deletes the sessions listed in a subject's index and
// the index itself. ARGV[1] is the prefix of session keys.
var deleteSubjectScript = redis.NewScript(`
for _, key in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
	redis.call('DEL', ARGV[1] .. key)
end
redis.call('DEL', KEYS[1])
return 1
`)

func (s *Store) Load(ctx context.Context, key string) (session.Record, error) {
	vals, err := s.client.HMGet(ctx, s.recordKey(key), "s", "v", "e", "d").Result()
	if err != nil {
		return session.Record{}, fmt.Errorf("redissession: loading session: %w", err)
	}
	r, ok, err := s.parse(vals)
	if err != nil {
		return session.Record{}, err
	}
	if !ok {
		return session.Record{}, session.ErrNotFound
	}
	return r, nil
}

// parse converts the fields of a session hash to a Record. ok is false if
// the session does not exist or has expired.
func (s *Store) parse(vals []any) (r session.Record, ok bool, err error) {
	var fields [4]string
	for i, v := range vals {
		str, isStr := v.(string)
		if !isStr {
			return session.Record{}, false, nil
		}
		fields[i] = str
	}
	version, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || version == 0 {
		return session.Record{}, false, fmt.Errorf("redissession: invalid version %q", fields[1])
	}
	expires, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return session.Record{}, false, fmt.Errorf("redissession: invalid expiry %q", fields[2])
	}
	r = session.Record{Subject: fields[0], Version: version, ExpiresAt: time.Unix(0, expires), Data: []byte(fields[3])}
	// Redis expires keys with millisecond precision; the record must not
	// outlive its ExpiresAt even briefly.
	return r, s.now().Before(r.ExpiresAt), nil
}

func (s *Store) Save(ctx context.Context, key string, r session.Record) error {
	if r.Version == 0 {
		return session.ErrConflict
	}
	ttl := max(r.ExpiresAt.Sub(s.now()), 0)
	ttlMillis := (ttl + time.Millisecond - 1) / time.Millisecond
	ok, err := saveScript.Run(ctx, s.client, []string{s.recordKey(key), s.subjectKey(r.Subject)},
		strconv.FormatUint(r.Version-1, 10), strconv.FormatUint(r.Version, 10), r.Subject,
		strconv.FormatInt(r.ExpiresAt.UnixNano(), 10), r.Data, int64(ttlMillis), key).Int()
	if err != nil {
		return fmt.Errorf("redissession: saving session: %w", err)
	}
	if ok == 0 {
		return session.ErrConflict
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, key string, version uint64) error {
	ok, err := deleteScript.Run(ctx, s.client, []string{s.recordKey(key)},
		strconv.FormatUint(version, 10), s.prefix+"s:", key).Int()
	if err != nil {
		return fmt.Errorf("redissession: deleting session: %w", err)
	}
	if ok == 0 {
		return session.ErrConflict
	}
	return nil
}

func (s *Store) List(ctx context.Context, subject string) (map[string]session.Record, error) {
	keys, err := s.client.ZRange(ctx, s.subjectKey(subject), 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("redissession: listing sessions: %w", err)
	}
	cmds := make([]*redis.SliceCmd, len(keys))
	_, err = s.client.Pipelined(ctx, func(p redis.Pipeliner) error {
		for i, key := range keys {
			cmds[i] = p.HMGet(ctx, s.recordKey(key), "s", "v", "e", "d")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("redissession: listing sessions: %w", err)
	}
	out := map[string]session.Record{}
	for i, cmd := range cmds {
		r, ok, err := s.parse(cmd.Val())
		if err != nil {
			return nil, err
		}
		if ok && r.Subject == subject {
			out[keys[i]] = r
		}
	}
	return out, nil
}

func (s *Store) DeleteSubject(ctx context.Context, subject string) error {
	if err := deleteSubjectScript.Run(ctx, s.client, []string{s.subjectKey(subject)}, s.prefix+"k:").Err(); err != nil {
		return fmt.Errorf("redissession: deleting sessions of subject: %w", err)
	}
	return nil
}
