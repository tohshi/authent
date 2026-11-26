package jwt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// KeySet supplies verification keys.
type KeySet interface {
	// VerificationKeys returns the candidate keys for a token whose header
	// carries kid. kid is empty when the token has no "kid" header.
	// Returning no keys and no error means no key matches.
	VerificationKeys(ctx context.Context, kid string) ([]JWK, error)
}

// StaticKeySet is a fixed set of keys.
type StaticKeySet struct {
	keys []JWK
}

// NewStaticKeySet returns a KeySet holding keys.
func NewStaticKeySet(keys ...JWK) *StaticKeySet {
	return &StaticKeySet{keys: slices.Clone(keys)}
}

func (s *StaticKeySet) VerificationKeys(_ context.Context, kid string) ([]JWK, error) {
	return matchKeys(s.keys, kid), nil
}

// matchKeys returns keys whose kid equals kid. A token without a kid may
// be verified by any key; a key without a kid may verify any token.
func matchKeys(keys []JWK, kid string) []JWK {
	if kid == "" {
		return keys
	}
	var out []JWK
	for _, k := range keys {
		if k.KeyID == kid || k.KeyID == "" {
			out = append(out, k)
		}
	}
	return out
}

func hasKeyID(keys []JWK, kid string) bool {
	return slices.ContainsFunc(keys, func(k JWK) bool { return k.KeyID == kid })
}

// RemoteKeySet fetches a JWK Set over HTTPS and caches it.
//
// The set is refreshed when it is no longer fresh (see
// WithMaxRefreshInterval), or when a token names a kid that is not cached
// (key rotation), but at most once per minimum refresh interval. If a
// refresh fails while cached keys exist, the cached keys keep being used.
type RemoteKeySet struct {
	url             string
	client          *http.Client
	refreshInterval time.Duration
	minInterval     time.Duration
	maxInterval     time.Duration
	maxBodySize     int64
	now             func() time.Time

	fetchMu sync.Mutex // serializes fetches

	mu        sync.RWMutex
	keys      []JWK
	fetchedAt time.Time // zero until the first successful fetch
	freshFor  time.Duration
	attempted time.Time // last fetch attempt, successful or not
}

// RemoteKeySetOption configures a RemoteKeySet.
type RemoteKeySetOption func(*RemoteKeySet)

// WithHTTPClient sets the HTTP client. The default is http.DefaultClient.
func WithHTTPClient(c *http.Client) RemoteKeySetOption {
	return func(r *RemoteKeySet) { r.client = c }
}

// WithRefreshInterval sets how long a fetched set is considered fresh when
// the response has no Cache-Control max-age. The default is 1 hour.
func WithRefreshInterval(d time.Duration) RemoteKeySetOption {
	return func(r *RemoteKeySet) { r.refreshInterval = d }
}

// WithMinRefreshInterval sets the minimum time between fetches, which
// bounds the load that tokens with unknown kids can cause. The default is
// 1 minute.
func WithMinRefreshInterval(d time.Duration) RemoteKeySetOption {
	return func(r *RemoteKeySet) { r.minInterval = d }
}

// WithMaxRefreshInterval caps the freshness lifetime taken from a
// Cache-Control max-age, which is raised to at least the minimum refresh
// interval; no-store and no-cache count as zero. The default is 24 hours.
func WithMaxRefreshInterval(d time.Duration) RemoteKeySetOption {
	return func(r *RemoteKeySet) { r.maxInterval = d }
}

// WithKeySetClock overrides the clock, for tests.
func WithKeySetClock(now func() time.Time) RemoteKeySetOption {
	return func(r *RemoteKeySet) { r.now = now }
}

// NewRemoteKeySet returns a RemoteKeySet for the JWK Set at rawURL, which
// must use https.
func NewRemoteKeySet(rawURL string, opts ...RemoteKeySetOption) (*RemoteKeySet, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("jwt: invalid JWKS URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("jwt: JWKS URL must be an absolute https URL: %q", rawURL)
	}
	r := &RemoteKeySet{
		url:             rawURL,
		client:          http.DefaultClient,
		refreshInterval: time.Hour,
		minInterval:     time.Minute,
		maxInterval:     24 * time.Hour,
		maxBodySize:     1 << 20,
		now:             time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.minInterval > r.maxInterval {
		return nil, errors.New("jwt: minimum refresh interval exceeds the maximum")
	}
	return r, nil
}

func (r *RemoteKeySet) VerificationKeys(ctx context.Context, kid string) ([]JWK, error) {
	r.mu.RLock()
	keys, fetchedAt, freshFor, attempted := r.keys, r.fetchedAt, r.freshFor, r.attempted
	r.mu.RUnlock()

	now := r.now()
	fresh := !fetchedAt.IsZero() && now.Sub(fetchedAt) < freshFor
	known := kid == "" || hasKeyID(keys, kid)
	throttled := !attempted.IsZero() && now.Sub(attempted) < r.minInterval

	if fresh && known {
		return matchKeys(keys, kid), nil
	}
	if throttled {
		if fetchedAt.IsZero() {
			return nil, errors.New("jwt: JWK set unavailable (previous fetch failed)")
		}
		return matchKeys(keys, kid), nil
	}

	keys, err := r.refresh(ctx, attempted)
	if err != nil {
		return nil, err
	}
	return matchKeys(keys, kid), nil
}

// refresh fetches the set unless another goroutine attempted a fetch after
// seenAttempt, in which case its result is reused.
func (r *RemoteKeySet) refresh(ctx context.Context, seenAttempt time.Time) ([]JWK, error) {
	r.fetchMu.Lock()
	defer r.fetchMu.Unlock()

	r.mu.RLock()
	keys, fetchedAt, attempted := r.keys, r.fetchedAt, r.attempted
	r.mu.RUnlock()
	if attempted.After(seenAttempt) {
		if fetchedAt.IsZero() {
			return nil, errors.New("jwt: fetching JWK set failed")
		}
		return keys, nil
	}

	fetched, freshFor, err := r.fetch(ctx)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempted = r.now()
	if err != nil {
		if r.fetchedAt.IsZero() {
			return nil, err
		}
		return r.keys, nil // keep serving the cached keys
	}
	r.keys, r.fetchedAt, r.freshFor = fetched, r.attempted, freshFor
	return fetched, nil
}

func (r *RemoteKeySet) fetch(ctx context.Context) ([]JWK, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("jwt: fetching JWK set: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("jwt: fetching JWK set: status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, r.maxBodySize+1))
	if err != nil {
		return nil, 0, fmt.Errorf("jwt: reading JWK set: %w", err)
	}
	if int64(len(body)) > r.maxBodySize {
		return nil, 0, errors.New("jwt: JWK set too large")
	}
	set, err := ParseJWKSet(body)
	if err != nil {
		return nil, 0, err
	}
	freshFor := r.refreshInterval
	if d, ok := cacheLifetime(resp.Header.Values("Cache-Control")); ok {
		freshFor = min(max(d, r.minInterval), r.maxInterval)
	}
	return set.Keys, freshFor, nil
}

// cacheLifetime returns the freshness lifetime set by Cache-Control
// values, if any. A repeated or invalid max-age counts as stale (RFC 9111
// §4.2.1).
func cacheLifetime(values []string) (time.Duration, bool) {
	var maxAge time.Duration
	found := false
	for _, v := range values {
		for directive := range strings.SplitSeq(v, ",") {
			name, arg, _ := strings.Cut(strings.TrimSpace(directive), "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "no-store", "no-cache":
				return 0, true
			case "max-age":
				secs, ok := parseDeltaSeconds(strings.TrimSpace(arg))
				if !ok || found {
					return 0, true
				}
				maxAge, found = time.Duration(secs)*time.Second, true
			}
		}
	}
	return maxAge, found
}

// parseDeltaSeconds parses delta-seconds, capping values above 2^31 as
// RFC 9111 §1.2.2 requires.
func parseDeltaSeconds(s string) (int64, bool) {
	const limit = 1 << 31
	if s == "" {
		return 0, false
	}
	var n int64
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = min(n*10+int64(c-'0'), limit)
	}
	return n, true
}
