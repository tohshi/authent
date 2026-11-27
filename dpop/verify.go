package dpop

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observe"
	"github.com/tohshi/authent/jwt"
)

// Default proof acceptance window.
const (
	DefaultMaxAge = time.Minute
	DefaultLeeway = 10 * time.Second
)

// Request is the part of an HTTP request that a proof is checked against.
type Request struct {
	// Method is the HTTP method, for example "GET".
	Method string
	// URL is the absolute target URI of the request as the client sent it,
	// for example "https://api.example.com/v1/items?page=2". Behind a
	// reverse proxy, build it from the externally visible scheme and host,
	// not from the proxy's view. Query and fragment are ignored.
	URL string
	// Proofs holds every value of the DPoP request header, for example
	// r.Header.Values("DPoP"). Exactly one is required.
	Proofs []string
	// AccessToken is the access token sent with the request, if any (see
	// AccessToken). When set, the proof must carry its hash in "ath".
	AccessToken string
	// JKT, if set, is the thumbprint the access token is bound to (its
	// "cnf" "jkt"). The proof must then be signed with that key.
	// Authenticator sets it from the token.
	JKT string
}

// Proof is a verified DPoP proof.
type Proof struct {
	// Key is the public key that signed the proof.
	Key jwt.JWK
	// JKT is the key's JWK SHA-256 thumbprint.
	JKT string
	// ID is the "jti" claim.
	ID string
	// IssuedAt is the "iat" claim.
	IssuedAt time.Time
	// Nonce is the "nonce" claim, if any.
	Nonce string
}

// Verifier checks DPoP proofs (RFC 9449 §4.3). It is safe for concurrent
// use.
type Verifier struct {
	algs     []jwt.Algorithm
	replay   jwt.ReplayCache
	noReplay bool
	nonce    func(ctx context.Context, nonce string) bool
	maxAge   time.Duration
	leeway   time.Duration
	now      func() time.Time
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithAlgorithms sets the accepted proof algorithms. It is required, and
// only asymmetric algorithms are allowed.
func WithAlgorithms(algs ...jwt.Algorithm) Option {
	return func(v *Verifier) { v.algs = append(v.algs, algs...) }
}

// WithReplayCache rejects proofs whose "jti" was already seen. Either
// WithReplayCache or WithoutReplayCheck is required.
func WithReplayCache(c jwt.ReplayCache) Option { return func(v *Verifier) { v.replay = c } }

// WithoutReplayCheck disables replay detection, for deployments where the
// servers behind an endpoint share no state. Proofs can then be replayed
// within the acceptance window; keep it short or require nonces.
func WithoutReplayCheck() Option { return func(v *Verifier) { v.noReplay = true } }

// WithNonce requires every proof to carry a nonce that valid accepts.
// Proofs without one fail with ErrUseNonce; respond with a fresh nonce in
// the DPoP-Nonce header. Nonces are opaque to the client, so valid may for
// example check an HMAC over a recent timestamp.
func WithNonce(valid func(ctx context.Context, nonce string) bool) Option {
	return func(v *Verifier) { v.nonce = valid }
}

// WithMaxAge sets how long after "iat" a proof is accepted. The default is
// DefaultMaxAge.
func WithMaxAge(d time.Duration) Option { return func(v *Verifier) { v.maxAge = d } }

// WithLeeway sets how far in the future "iat" may be, to tolerate clock
// skew. The default is DefaultLeeway.
func WithLeeway(d time.Duration) Option { return func(v *Verifier) { v.leeway = d } }

// WithClock overrides the clock, for tests.
func WithClock(now func() time.Time) Option { return func(v *Verifier) { v.now = now } }

// NewVerifier returns a Verifier. WithAlgorithms is required, as is a
// replay policy (WithReplayCache or WithoutReplayCheck), so that skipping
// replay detection is always an explicit decision.
func NewVerifier(opts ...Option) (*Verifier, error) {
	v := &Verifier{maxAge: DefaultMaxAge, leeway: DefaultLeeway, now: time.Now}
	for _, opt := range opts {
		opt(v)
	}
	if len(v.algs) == 0 {
		return nil, errors.New("dpop: WithAlgorithms is required")
	}
	for _, a := range v.algs {
		if a.IsSymmetric() || (a.Hash() == 0 && a != jwt.EdDSA) {
			return nil, fmt.Errorf("dpop: unsupported proof algorithm %q", a)
		}
	}
	if (v.replay == nil) == !v.noReplay {
		return nil, errors.New("dpop: exactly one of WithReplayCache or WithoutReplayCheck is required")
	}
	if v.maxAge <= 0 || v.leeway < 0 {
		return nil, errors.New("dpop: invalid max age or leeway")
	}
	return v, nil
}

// Verify checks the proof in r. Rejections wrap authent.ErrUnauthenticated
// (ErrInvalidProof, ErrUseNonce or ErrKeyBinding); replay cache failures
// do not.
func (v *Verifier) Verify(ctx context.Context, r Request) (*Proof, error) {
	if len(r.Proofs) != 1 {
		return nil, fmt.Errorf("%w: %d DPoP headers", ErrInvalidProof, len(r.Proofs))
	}
	jws, err := jwt.VerifyWithEmbeddedKey(r.Proofs[0], v.algs...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}
	if !strings.EqualFold(jws.Header.Type, proofType) {
		return nil, fmt.Errorf("%w: typ %q", ErrInvalidProof, jws.Header.Type)
	}
	var c proofClaims
	if err := json.Unmarshal(jws.Payload, &c); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrInvalidProof, err)
	}
	if c.JTI == "" || c.HTM == "" || c.HTU == "" || c.IAT.IsZero() {
		return nil, fmt.Errorf("%w: missing jti, htm, htu or iat", ErrInvalidProof)
	}
	if c.HTM != r.Method {
		return nil, fmt.Errorf("%w: htm %q, request method %q", ErrInvalidProof, c.HTM, r.Method)
	}
	want, err := normalizeURI(r.URL)
	if err != nil {
		return nil, fmt.Errorf("dpop: request URL: %w", err)
	}
	if got, err := normalizeURI(c.HTU); err != nil || got != want {
		return nil, fmt.Errorf("%w: htu %q does not match %q", ErrInvalidProof, c.HTU, want)
	}
	now := v.now()
	if c.IAT.Before(now.Add(-v.maxAge)) || c.IAT.After(now.Add(v.leeway)) {
		return nil, fmt.Errorf("%w: iat outside the acceptance window", ErrInvalidProof)
	}
	if r.AccessToken != "" && subtle.ConstantTimeCompare([]byte(c.ATH), []byte(AccessTokenHash(r.AccessToken))) != 1 {
		return nil, fmt.Errorf("%w: ath does not match the access token", ErrInvalidProof)
	}
	if v.nonce != nil && (c.Nonce == "" || !v.nonce(ctx, c.Nonce)) {
		return nil, ErrUseNonce
	}
	jkt, err := Thumbprint(jws.Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	if r.JKT != "" && subtle.ConstantTimeCompare([]byte(jkt), []byte(r.JKT)) != 1 {
		return nil, ErrKeyBinding
	}
	// Recorded last, so that proofs failing any other check do not fill
	// the cache.
	if v.replay != nil {
		key := sha256.Sum256([]byte(jkt + "\x00" + c.JTI))
		ttl := c.IAT.Add(v.maxAge).Sub(now)
		fresh, err := v.replay.Add(ctx, base64.RawURLEncoding.EncodeToString(key[:]), ttl)
		if err != nil {
			return nil, fmt.Errorf("dpop: replay cache: %w", err)
		}
		if !fresh {
			return nil, ErrReplayed
		}
	}
	return &Proof{Key: jws.Key, JKT: jkt, ID: c.JTI, IssuedAt: c.IAT.Time, Nonce: c.Nonce}, nil
}

// Challenge returns a WWW-Authenticate header value for a request that
// failed with err (RFC 9449 §7.1). Pass nil when the request carried no
// credentials. Respond with 401, and when err is ErrUseNonce, include a
// fresh nonce in the DPoP-Nonce header.
func (v *Verifier) Challenge(err error) string {
	algs := make([]string, len(v.algs))
	for i, a := range v.algs {
		algs[i] = string(a)
	}
	params := `algs="` + strings.Join(algs, " ") + `"`
	var code string
	switch {
	case err == nil, errors.Is(err, ErrNoToken), !errors.Is(err, authent.ErrUnauthenticated):
		// No credentials, or a server failure that is not the client's.
		return TokenType + " " + params
	case errors.Is(err, ErrUseNonce):
		code = "use_dpop_nonce"
	case errors.Is(err, ErrInvalidProof):
		code = "invalid_dpop_proof"
	default:
		code = "invalid_token"
	}
	return TokenType + ` error="` + code + `", ` + params
}

// Authenticator authenticates requests to a resource server that carry a
// DPoP-bound access token (RFC 9449 §7). It is safe for concurrent use.
type Authenticator struct {
	tokens   TokenVerifier
	proofs   *Verifier
	observer authent.Observer
}

// AuthenticatorOption configures an Authenticator.
type AuthenticatorOption func(*Authenticator)

// WithObserver sends an Event for every Authenticate call to o.
func WithObserver(o authent.Observer) AuthenticatorOption {
	return func(a *Authenticator) { a.observer = o }
}

// NewAuthenticator returns an Authenticator. tokens must accept tokens
// with a "cnf" claim (jwt.WithConfirmationClaim, or
// IntrospectionConfig.ConfirmationClaim), or every token is rejected with
// jwt.ErrSenderConstrained. Do not give a *jwt.Verifier a
// jwt.WithReplayCache: the token is recorded before the proof is checked,
// so a stolen token sent with a bad proof would lock out its holder.
func NewAuthenticator(tokens TokenVerifier, proofs *Verifier, opts ...AuthenticatorOption) (*Authenticator, error) {
	// A typed nil such as (*jwt.Verifier)(nil) is a non-nil interface.
	if v := reflect.ValueOf(tokens); tokens == nil || v.Kind() == reflect.Pointer && v.IsNil() || proofs == nil {
		return nil, errors.New("dpop: nil verifier")
	}
	a := &Authenticator{tokens: tokens, proofs: proofs}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Authenticate verifies the access token in r, which must be bound to a
// key with the "cnf" "jkt" claim, and the proof, which must be signed with
// that key and carry the token's hash. Extract the token from the
// Authorization header with AccessToken.
func (a *Authenticator) Authenticate(ctx context.Context, r Request) (authent.Principal, error) {
	start := observe.Start(a.observer)
	p, err := a.authenticate(ctx, r)
	observe.Done(ctx, a.observer, authent.KindAuthentication, authent.MethodDPoP, start, p.Subject, err)
	return p, err
}

func (a *Authenticator) authenticate(ctx context.Context, r Request) (authent.Principal, error) {
	if r.AccessToken == "" {
		return authent.Principal{}, ErrNoToken
	}
	claims, err := a.tokens.Verify(ctx, r.AccessToken)
	if err != nil {
		return authent.Principal{}, err
	}
	cnf, _ := claims.Extra["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	if jkt == "" {
		return authent.Principal{}, fmt.Errorf("%w: token has no cnf jkt", ErrKeyBinding)
	}
	r.JKT = jkt
	if _, err := a.proofs.Verify(ctx, r); err != nil {
		return authent.Principal{}, err
	}
	return jwt.PrincipalFromClaims(claims, authent.MethodDPoP)
}

func init() {
	observe.Register(map[error]authent.Reason{
		ErrInvalidProof:  authent.ReasonInvalidProof,
		ErrReplayed:      authent.ReasonReplayed,
		ErrUseNonce:      authent.ReasonNonceRequired,
		ErrKeyBinding:    authent.ReasonKeyMismatch,
		ErrNoToken:       authent.ReasonNoCredentials,
		ErrInactiveToken: authent.ReasonInactive,
	})
}
