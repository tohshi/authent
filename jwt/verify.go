package jwt

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tohshi/authent"
)

// Verifier verifies JWTs. It is safe for concurrent use.
type Verifier struct {
	keys        KeySet
	algs        []Algorithm
	issuers     []string
	anyIssuer   bool
	audiences   []string
	anyAudience bool
	typ         string
	allowCnf    bool
	leeway      time.Duration
	maxSize     int
	replay      ReplayCache
	maxTokenAge *time.Duration
	maxAuthAge  *time.Duration
	roots       *x509.CertPool
	now         func() time.Time
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithAlgorithms sets the accepted algorithms. It is required.
func WithAlgorithms(algs ...Algorithm) VerifierOption {
	return func(v *Verifier) { v.algs = append(v.algs, algs...) }
}

// WithIssuer accepts tokens whose "iss" equals one of issuers.
// Either WithIssuer or WithAnyIssuer is required.
func WithIssuer(issuers ...string) VerifierOption {
	return func(v *Verifier) { v.issuers = append(v.issuers, issuers...) }
}

// WithAnyIssuer disables the "iss" check.
func WithAnyIssuer() VerifierOption { return func(v *Verifier) { v.anyIssuer = true } }

// WithAudience accepts tokens whose "aud" contains one of audiences.
// Either WithAudience or WithAnyAudience is required.
func WithAudience(audiences ...string) VerifierOption {
	return func(v *Verifier) { v.audiences = append(v.audiences, audiences...) }
}

// WithAnyAudience disables the "aud" check.
func WithAnyAudience() VerifierOption { return func(v *Verifier) { v.anyAudience = true } }

// WithExpectedType requires the "typ" header to equal typ, compared
// case-insensitively and ignoring an "application/" prefix (RFC 7515
// §4.1.9), for example "at+jwt" for OAuth access tokens (RFC 9068).
func WithExpectedType(typ string) VerifierOption { return func(v *Verifier) { v.typ = typ } }

// WithConfirmationClaim accepts tokens that carry a "cnf" (confirmation)
// claim (RFC 7800). Such tokens are sender-constrained, for example bound
// to a DPoP key (RFC 9449) or a TLS client certificate (RFC 8705), and are
// only valid together with proof of possession of that key, which Verifier
// does not check. By default they are rejected with ErrSenderConstrained so
// that a stolen bound token cannot be replayed as a bearer token (RFC 9449
// §7.2). Use this option only when the caller verifies the binding, as
// dpop.Authenticator does.
func WithConfirmationClaim() VerifierOption { return func(v *Verifier) { v.allowCnf = true } }

// WithLeeway tolerates clock skew when checking exp, nbf and iat.
func WithLeeway(d time.Duration) VerifierOption { return func(v *Verifier) { v.leeway = d } }

// WithMaxTokenSize bounds the token length. The default is
// DefaultMaxTokenSize.
func WithMaxTokenSize(n int) VerifierOption { return func(v *Verifier) { v.maxSize = n } }

// WithMaxTokenAge rejects tokens issued more than d ago, plus the leeway,
// with ErrTokenTooOld. "iat" becomes required.
func WithMaxTokenAge(d time.Duration) VerifierOption {
	return func(v *Verifier) { v.maxTokenAge = &d }
}

// WithMaxAuthAge rejects tokens whose subject authenticated more than d
// ago, plus the leeway, with ErrAuthenticationTooOld, as OpenID Connect
// "max_age" requires. "auth_time" becomes required, and one later than
// now plus the leeway fails with ErrIssuedInFuture. Zero accepts only an
// authentication within the leeway.
func WithMaxAuthAge(d time.Duration) VerifierOption {
	return func(v *Verifier) { v.maxAuthAge = &d }
}

// WithCertificateRoots only uses keys whose "x5c" certificate chain
// verifies to one of roots at the Verifier's clock, with a leaf that
// allows digital signatures. Keys without "x5c" are not used. The "x5c"
// header of a token is never used to find keys.
func WithCertificateRoots(roots *x509.CertPool) VerifierOption {
	return func(v *Verifier) { v.roots = roots }
}

// WithReplayCache accepts each token only once. "jti" becomes required,
// and the pair of "iss" and "jti" is recorded in c until "exp" (plus the
// leeway) once every other check has passed. A replayed token fails with
// ErrReplayed. Errors from c reject the token and are returned as is.
//
// Use it for single-use tokens such as ID tokens, logout tokens, client
// assertions and request objects, not for access tokens, which a client
// sends many times.
func WithReplayCache(c ReplayCache) VerifierOption { return func(v *Verifier) { v.replay = c } }

// WithClock overrides the clock, for tests.
func WithClock(now func() time.Time) VerifierOption { return func(v *Verifier) { v.now = now } }

// NewVerifier returns a Verifier using keys. WithAlgorithms is required,
// as are an issuer and audience policy (WithIssuer or WithAnyIssuer, and
// WithAudience or WithAnyAudience), so that omitting a check is always an
// explicit decision.
func NewVerifier(keys KeySet, opts ...VerifierOption) (*Verifier, error) {
	v := &Verifier{keys: keys, maxSize: DefaultMaxTokenSize, now: time.Now}
	for _, opt := range opts {
		opt(v)
	}
	if keys == nil {
		return nil, errors.New("jwt: nil KeySet")
	}
	if len(v.algs) == 0 {
		return nil, errors.New("jwt: WithAlgorithms is required")
	}
	for _, a := range v.algs {
		if _, ok := a.spec(); !ok {
			return nil, fmt.Errorf("jwt: unsupported algorithm %q", a)
		}
	}
	if len(v.issuers) == 0 && !v.anyIssuer {
		return nil, errors.New("jwt: WithIssuer or WithAnyIssuer is required")
	}
	if len(v.audiences) == 0 && !v.anyAudience {
		return nil, errors.New("jwt: WithAudience or WithAnyAudience is required")
	}
	if v.leeway < 0 {
		return nil, errors.New("jwt: negative leeway")
	}
	if (v.maxTokenAge != nil && *v.maxTokenAge < 0) || (v.maxAuthAge != nil && *v.maxAuthAge < 0) {
		return nil, errors.New("jwt: negative maximum age")
	}
	return v, nil
}

// Verify checks the token's signature and claims and returns the claims.
// Rejections wrap ErrInvalidToken. Errors from the KeySet or the
// ReplayCache, such as network failures, are returned as is.
//
// "exp" is always required. Tokens with a "cnf" claim are rejected unless
// WithConfirmationClaim is set.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	claims, _, err := v.VerifyWithHeader(ctx, token)
	return claims, err
}

// Header is the verified JOSE header of a token.
type Header struct {
	Algorithm Algorithm
	KeyID     string
	Type      string
}

// VerifyWithHeader is like Verify but also returns the token's header.
func (v *Verifier) VerifyWithHeader(ctx context.Context, token string) (*Claims, Header, error) {
	return v.verifyToken(ctx, token, false)
}

func (v *Verifier) verifyToken(ctx context.Context, token string, requireSubject bool) (*Claims, Header, error) {
	c, err := v.verify(ctx, token)
	if err != nil {
		return nil, Header{}, err
	}
	var claims Claims
	if err := json.Unmarshal(c.payload, &claims); err != nil {
		return nil, Header{}, fmt.Errorf("%w: claims: %v", ErrMalformed, err)
	}
	if err := v.validate(&claims); err != nil {
		return nil, Header{}, err
	}
	if requireSubject && claims.Subject == "" {
		return nil, Header{}, fmt.Errorf("%w: sub", ErrMissingClaim)
	}
	// Last, so a token failing other checks does not burn its jti.
	if err := v.checkReplay(ctx, &claims); err != nil {
		return nil, Header{}, err
	}
	return &claims, Header{Algorithm: c.header.Alg, KeyID: c.header.Kid, Type: c.header.Typ}, nil
}

func (v *Verifier) checkReplay(ctx context.Context, c *Claims) error {
	if v.replay == nil {
		return nil
	}
	// "jti" is unique per issuer (RFC 7519 §4.1.7). The length prefix
	// keeps distinct (iss, jti) pairs from hashing the same input.
	id := sha256.Sum256([]byte(strconv.Itoa(len(c.Issuer)) + ":" + c.Issuer + c.ID))
	fresh, err := v.replay.Add(ctx, b64.EncodeToString(id[:]), c.ExpiresAt.Add(v.leeway).Sub(v.now()))
	if err != nil {
		return fmt.Errorf("jwt: replay cache: %w", err)
	}
	if !fresh {
		return ErrReplayed
	}
	return nil
}

// verify parses token and checks its header and signature.
func (v *Verifier) verify(ctx context.Context, token string) (*compact, error) {
	c, err := parseCompact(token, v.maxSize)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(v.algs, c.header.Alg) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, c.header.Alg)
	}
	if v.typ != "" && !typeMatches(c.header.Typ, v.typ) {
		return nil, fmt.Errorf("%w: %q", ErrUnexpectedType, c.header.Typ)
	}
	if err := v.verifySignature(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (v *Verifier) verifySignature(ctx context.Context, c *compact) error {
	keys, err := v.keys.VerificationKeys(ctx, c.header.Kid)
	if err != nil {
		return err
	}
	tried := false
	var untrusted error
	for _, k := range keys {
		if !k.canVerify(c.header.Alg) {
			continue
		}
		if v.roots != nil {
			if err := k.verifyChain(v.roots, v.now()); err != nil {
				untrusted = err
				continue
			}
		}
		tried = true
		if verify(c.header.Alg, k.Key, []byte(c.signingInput), c.signature) == nil {
			return nil
		}
	}
	if !tried && untrusted != nil {
		return fmt.Errorf("%w: kid %q: %v", ErrNoMatchingKey, c.header.Kid, untrusted)
	}
	if !tried {
		return fmt.Errorf("%w: kid %q alg %q", ErrNoMatchingKey, c.header.Kid, c.header.Alg)
	}
	return ErrInvalidSignature
}

func (v *Verifier) validate(c *Claims) error {
	now := v.now()
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: exp", ErrMissingClaim)
	}
	if !now.Before(c.ExpiresAt.Add(v.leeway)) {
		return ErrExpired
	}
	if !c.NotBefore.IsZero() && now.Add(v.leeway).Before(c.NotBefore.Time) {
		return ErrNotYetValid
	}
	if !c.IssuedAt.IsZero() && now.Add(v.leeway).Before(c.IssuedAt.Time) {
		return ErrIssuedInFuture
	}
	if v.maxTokenAge != nil {
		if c.IssuedAt.IsZero() {
			return fmt.Errorf("%w: iat", ErrMissingClaim)
		}
		if v.olderThan(now, c.IssuedAt.Time, *v.maxTokenAge) {
			return ErrTokenTooOld
		}
	}
	if v.maxAuthAge != nil {
		at, err := c.AuthTime()
		if err != nil {
			return err
		}
		if at.IsZero() {
			return fmt.Errorf("%w: auth_time", ErrMissingClaim)
		}
		if now.Add(v.leeway).Before(at) {
			return fmt.Errorf("%w: auth_time", ErrIssuedInFuture)
		}
		if v.olderThan(now, at, *v.maxAuthAge) {
			return ErrAuthenticationTooOld
		}
	}
	if !v.anyIssuer && !slices.Contains(v.issuers, c.Issuer) {
		return fmt.Errorf("%w: %q", ErrInvalidIssuer, c.Issuer)
	}
	if _, bound := c.Extra["cnf"]; bound && !v.allowCnf {
		return ErrSenderConstrained
	}
	if !v.anyAudience && !slices.ContainsFunc(c.Audience, func(a string) bool {
		return slices.Contains(v.audiences, a)
	}) {
		return fmt.Errorf("%w: %q", ErrInvalidAudience, c.Audience)
	}
	if v.replay != nil && c.ID == "" {
		return fmt.Errorf("%w: jti", ErrMissingClaim)
	}
	return nil
}

// olderThan reports whether more than limit plus the leeway passed since
// t. It compares differences so that a limit near math.MaxInt64 cannot
// overflow into a negative limit.
func (v *Verifier) olderThan(now, t time.Time, limit time.Duration) bool {
	age := now.Sub(t)
	return age > limit && age-limit > v.leeway
}

// Authenticate verifies token and returns its Principal. "sub" is
// required. AuthTime is taken from "auth_time" if present, else "iat".
func (v *Verifier) Authenticate(ctx context.Context, token string) (authent.Principal, error) {
	c, _, err := v.verifyToken(ctx, token, true)
	if err != nil {
		return authent.Principal{}, err
	}
	return PrincipalFromClaims(c, authent.MethodJWT)
}

// PrincipalFromClaims converts verified claims to a Principal.
func PrincipalFromClaims(c *Claims, method authent.Method) (authent.Principal, error) {
	if c.Subject == "" {
		return authent.Principal{}, fmt.Errorf("%w: sub", ErrMissingClaim)
	}
	all, err := c.AsMap()
	if err != nil {
		return authent.Principal{}, err
	}
	authTime := c.IssuedAt.Time
	if at, err := c.AuthTime(); err == nil && !at.IsZero() {
		authTime = at
	}
	return authent.Principal{
		Subject:  c.Subject,
		Issuer:   c.Issuer,
		Method:   method,
		AuthTime: authTime,
		Claims:   all,
	}, nil
}

func typeMatches(got, want string) bool {
	norm := func(s string) string {
		const prefix = "application/"
		if len(s) > len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
			s = s[len(prefix):]
		}
		return s
	}
	return strings.EqualFold(norm(got), norm(want))
}
