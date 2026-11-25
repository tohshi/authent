package jwt

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
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
	leeway      time.Duration
	maxSize     int
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

// WithLeeway tolerates clock skew when checking exp, nbf and iat.
func WithLeeway(d time.Duration) VerifierOption { return func(v *Verifier) { v.leeway = d } }

// WithMaxTokenSize bounds the token length. The default is
// DefaultMaxTokenSize.
func WithMaxTokenSize(n int) VerifierOption { return func(v *Verifier) { v.maxSize = n } }

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
	return v, nil
}

// Verify checks the token's signature and claims and returns the claims.
// Rejections wrap ErrInvalidToken. Errors from the KeySet, such as network
// failures, are returned as is.
//
// "exp" is always required.
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
	return &claims, Header{Algorithm: c.header.Alg, KeyID: c.header.Kid, Type: c.header.Typ}, nil
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
	for _, k := range keys {
		if !k.canVerify(c.header.Alg) {
			continue
		}
		tried = true
		if verify(c.header.Alg, k.Key, []byte(c.signingInput), c.signature) == nil {
			return nil
		}
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
	if !v.anyIssuer && !slices.Contains(v.issuers, c.Issuer) {
		return fmt.Errorf("%w: %q", ErrInvalidIssuer, c.Issuer)
	}
	if !v.anyAudience && !slices.ContainsFunc(c.Audience, func(a string) bool {
		return slices.Contains(v.audiences, a)
	}) {
		return fmt.Errorf("%w: %q", ErrInvalidAudience, c.Audience)
	}
	return nil
}

// Authenticate verifies token and returns its Principal. "sub" is
// required. AuthTime is taken from "auth_time" if present, else "iat".
func (v *Verifier) Authenticate(ctx context.Context, token string) (authent.Principal, error) {
	c, err := v.Verify(ctx, token)
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
	if at, ok := c.Extra["auth_time"].(float64); ok && at > 0 && at <= maxUnixSeconds {
		authTime = time.Unix(int64(at), 0).UTC()
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
