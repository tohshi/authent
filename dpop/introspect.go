package dpop

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

// ErrInactiveToken means the authorization server reported the access
// token as inactive, or its introspection response did not pass the
// Introspector's checks. It wraps authent.ErrUnauthenticated.
var ErrInactiveToken = fmt.Errorf("dpop: access token not active: %w", authent.ErrUnauthenticated)

// TokenVerifier checks an access token and returns its claims. A
// *jwt.Verifier checks JWT access tokens and an *Introspector checks
// opaque ones.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (*jwt.Claims, error)
}

// IntrospectionConfig configures an Introspector.
type IntrospectionConfig struct {
	// Endpoint is the URL of the authorization server's token
	// introspection endpoint (RFC 7662).
	Endpoint string
	// ClientID and ClientSecret authenticate the resource server with
	// client_secret_basic. Both are required.
	ClientID     string
	ClientSecret string
	// Issuer, if set, must equal the "iss" member of every response that
	// has one.
	Issuer string
	// Audiences lists the accepted "aud" values; a response must contain
	// one of them. Either Audiences or AnyAudience is required.
	Audiences []string
	// AnyAudience disables the "aud" check.
	AnyAudience bool
	// ConfirmationClaim accepts tokens with a "cnf" claim. Set it only when
	// the caller checks the binding, as Authenticator does. Otherwise
	// bound tokens fail with jwt.ErrSenderConstrained, so a stolen bound
	// token is not accepted as a bearer token.
	ConfirmationClaim bool
	// HTTPClient sends the requests. The default is http.DefaultClient.
	HTTPClient *http.Client
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Introspector checks opaque access tokens at a token introspection
// endpoint (RFC 7662). It is safe for concurrent use.
type Introspector struct {
	cfg IntrospectionConfig
}

// NewIntrospector returns an Introspector.
func NewIntrospector(cfg IntrospectionConfig) (*Introspector, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("dpop: introspection endpoint must be an absolute http or https URL")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("dpop: introspection needs ClientID and ClientSecret")
	}
	if len(cfg.Audiences) == 0 && !cfg.AnyAudience {
		return nil, errors.New("dpop: Audiences or AnyAudience is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Introspector{cfg: cfg}, nil
}

// Verify introspects token and returns the response members as claims.
// "active" must be true, and "iss", "aud", "exp", "nbf", "scope" and
// "cnf" are checked as configured. Rejections wrap
// authent.ErrUnauthenticated; failures to reach the endpoint or to parse
// its response do not.
func (in *Introspector) Verify(ctx context.Context, token string) (*jwt.Claims, error) {
	body, err := in.post(ctx, token)
	if err != nil {
		return nil, err
	}
	return in.parse(body)
}

func (in *Introspector) parse(body []byte) (*jwt.Claims, error) {
	var c jwt.Claims
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("dpop: introspection response: %w", err)
	}
	active, ok := c.Extra["active"].(bool)
	if !ok {
		return nil, errors.New(`dpop: introspection response lacks a boolean "active"`)
	}
	if !active {
		return nil, ErrInactiveToken
	}
	if err := in.validate(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (in *Introspector) validate(c *jwt.Claims) error {
	if scope, ok := c.Extra["scope"]; ok {
		if _, ok := scope.(string); !ok {
			return fmt.Errorf("%w: scope is not a string", ErrInactiveToken)
		}
	}
	now := in.cfg.Now()
	if !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt.Add(DefaultLeeway)) {
		return fmt.Errorf("%w: expired", ErrInactiveToken)
	}
	if !c.NotBefore.IsZero() && now.Add(DefaultLeeway).Before(c.NotBefore.Time) {
		return fmt.Errorf("%w: not yet valid", ErrInactiveToken)
	}
	if in.cfg.Issuer != "" && c.Issuer != "" && c.Issuer != in.cfg.Issuer {
		return fmt.Errorf("%w: iss %q", ErrInactiveToken, c.Issuer)
	}
	if !in.cfg.AnyAudience && !slices.ContainsFunc(c.Audience, func(a string) bool {
		return slices.Contains(in.cfg.Audiences, a)
	}) {
		return fmt.Errorf("%w: aud %q", ErrInactiveToken, c.Audience)
	}
	if _, bound := c.Extra["cnf"]; bound && !in.cfg.ConfirmationClaim {
		return jwt.ErrSenderConstrained
	}
	return nil
}

func (in *Introspector) post(ctx context.Context, token string) ([]byte, error) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.cfg.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1: both values are form-encoded first.
	req.SetBasicAuth(url.QueryEscape(in.cfg.ClientID), url.QueryEscape(in.cfg.ClientSecret))
	resp, err := in.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dpop: introspection: %w", err)
	}
	defer resp.Body.Close()
	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("dpop: introspection: %w", err)
	}
	if len(body) > maxBody {
		return nil, errors.New("dpop: introspection response too large")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dpop: introspection: status %d", resp.StatusCode)
	}
	return body, nil
}
