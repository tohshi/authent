// Package httpauth adapts the authent authenticators to net/http.
//
// An Authenticator turns a request into an authent.Principal. Require and
// Optional wrap a handler, store the Principal in the request context
// (read it with authent.FromContext) and turn errors into responses:
// errors wrapping authent.ErrUnauthenticated give 401, ErrForbidden gives
// 403, and anything else gives 500 without details.
package httpauth

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/apikey"
	"github.com/tohshi/authent/internal/observe"
	"github.com/tohshi/authent/jwt"
	"github.com/tohshi/authent/session"
)

var (
	// ErrNoCredentials is returned by an Authenticator when the request
	// carries none of the credentials it handles. It wraps
	// authent.ErrUnauthenticated. Optional lets such requests through
	// without a Principal; every other authentication error is rejected.
	ErrNoCredentials = fmt.Errorf("httpauth: no credentials: %w", authent.ErrUnauthenticated)
	// ErrForbidden is returned when an authenticated request is not
	// allowed. The default error handler responds with 403.
	ErrForbidden = errors.New("httpauth: forbidden")
	// ErrCSRF is returned for a session-authenticated request with an
	// unsafe method and a missing or wrong CSRF token. It wraps
	// ErrForbidden.
	ErrCSRF = fmt.Errorf("%w: CSRF token mismatch", ErrForbidden)

	// errEmptySubject is an Authenticator bug, not a client error, so it
	// gives 500 instead of granting an anonymous Principal.
	errEmptySubject = errors.New("httpauth: authenticator returned a Principal without a subject")

	errMalformedHeader = fmt.Errorf("httpauth: malformed Authorization header: %w", authent.ErrUnauthenticated)
)

// Authenticator authenticates the credentials carried by a request.
type Authenticator interface {
	// AuthenticateRequest returns ErrNoCredentials if the request carries
	// none of the credentials this Authenticator handles.
	AuthenticateRequest(r *http.Request) (authent.Principal, error)
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(r *http.Request) (authent.Principal, error)

func (f AuthenticatorFunc) AuthenticateRequest(r *http.Request) (authent.Principal, error) {
	return f(r)
}

// Challenger is implemented by Authenticators that have an HTTP
// authentication scheme. Challenge returns the WWW-Authenticate value for
// a 401 response caused by err, or "" for none.
type Challenger interface {
	Challenge(err error) string
}

// ErrorHandler writes the response for a rejected request.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

type config struct {
	onError  ErrorHandler
	observer authent.Observer
}

// Option configures Require, Optional and RequirePermission.
type Option func(*config)

// WithErrorHandler replaces the default error responses.
func WithErrorHandler(h ErrorHandler) Option { return func(c *config) { c.onError = h } }

// WithObserver sends an Event of kind authent.KindHTTPRequest for every
// request to o. Requests rejected with ErrForbidden have the outcome
// authent.OutcomeRejected, and an anonymous request that Optional lets
// through is a success without a Subject.
func WithObserver(o authent.Observer) Option { return func(c *config) { c.observer = o } }

func (c *config) observe(r *http.Request, start time.Time, p authent.Principal, err error) {
	if c.observer == nil {
		return
	}
	e := observe.Result(authent.KindHTTPRequest, p.Method, start, p.Subject, err)
	if errors.Is(err, ErrForbidden) {
		e.Outcome = authent.OutcomeRejected
	}
	observe.Emit(r.Context(), c.observer, e)
}

func newConfig(a Authenticator, opts []Option) config {
	c := config{onError: defaultErrorHandler(a)}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

func defaultErrorHandler(a Authenticator) ErrorHandler {
	return func(w http.ResponseWriter, _ *http.Request, err error) {
		switch {
		case errors.Is(err, authent.ErrUnauthenticated):
			if c, ok := a.(Challenger); ok {
				if ch := c.Challenge(err); ch != "" {
					w.Header().Set("WWW-Authenticate", ch)
				}
			}
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		case errors.Is(err, ErrForbidden):
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		default:
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}
}

// Require returns middleware that rejects requests that a does not
// authenticate.
func Require(a Authenticator, opts ...Option) func(http.Handler) http.Handler {
	return middleware(a, true, opts)
}

// Optional returns middleware that authenticates requests carrying
// credentials and passes requests without any (ErrNoCredentials) through
// without a Principal. Requests with rejected credentials are not passed
// through.
func Optional(a Authenticator, opts ...Option) func(http.Handler) http.Handler {
	return middleware(a, false, opts)
}

func middleware(a Authenticator, required bool, opts []Option) func(http.Handler) http.Handler {
	c := newConfig(a, opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := observe.Start(c.observer)
			p, err := a.AuthenticateRequest(r)
			anonymous := !required && errors.Is(err, ErrNoCredentials)
			switch {
			case anonymous:
				err = nil
			case err == nil && p.Subject == "":
				err = errEmptySubject
			}
			c.observe(r, start, p, err)
			switch {
			case err != nil:
				c.onError(w, r, err)
			case anonymous:
				next.ServeHTTP(w, r)
			default:
				next.ServeHTTP(w, r.WithContext(authent.NewContext(r.Context(), p)))
			}
		})
	}
}

// Any returns an Authenticator that tries each of auths in order. The
// first one that finds its credentials decides the result. List
// Authenticators that recognize their credentials by format, such as
// APIKey, before those that accept any bearer token.
func Any(auths ...Authenticator) Authenticator { return anyOf(auths) }

type anyOf []Authenticator

func (a anyOf) AuthenticateRequest(r *http.Request) (authent.Principal, error) {
	for _, auth := range a {
		p, err := auth.AuthenticateRequest(r)
		if !errors.Is(err, ErrNoCredentials) {
			return p, err
		}
	}
	return authent.Principal{}, ErrNoCredentials
}

func (a anyOf) Challenge(err error) string {
	var out []string
	for _, auth := range a {
		c, ok := auth.(Challenger)
		if !ok {
			continue
		}
		if ch := c.Challenge(err); ch != "" && !slices.Contains(out, ch) {
			out = append(out, ch)
		}
	}
	return strings.Join(out, ", ")
}

// BearerToken extracts the token from an Authorization header value that
// uses the Bearer scheme (RFC 6750 §2.1). Other schemes and an empty value
// return ErrNoCredentials; the Bearer scheme with a missing or malformed
// token is rejected.
func BearerToken(authorization string) (string, error) {
	scheme, token := authorization, ""
	if i := strings.IndexAny(authorization, " \t"); i >= 0 {
		scheme, token = authorization[:i], authorization[i:]
	}
	if !strings.EqualFold(scheme, "Bearer") {
		return "", ErrNoCredentials
	}
	token = strings.TrimLeft(token, " ")
	if !isToken68(token) {
		return "", invalidToken{errMalformedHeader}
	}
	return token, nil
}

// isToken68 reports whether s matches the b64token rule of RFC 6750 §2.1.
func isToken68(s string) bool {
	s = strings.TrimRight(s, "=")
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/') {
			return false
		}
	}
	return true
}

func bearerToken(r *http.Request) (string, error) {
	switch vals := r.Header.Values("Authorization"); len(vals) {
	case 0:
		return "", ErrNoCredentials
	case 1:
		return BearerToken(vals[0])
	default:
		return "", invalidToken{fmt.Errorf("%w: several headers", errMalformedHeader)}
	}
}

type invalidToken struct{ err error }

func (e invalidToken) Error() string { return e.err.Error() }
func (e invalidToken) Unwrap() error { return e.err }

func rejectedToken(err error) error {
	if errors.Is(err, authent.ErrUnauthenticated) {
		return invalidToken{err}
	}
	return err
}

// bearerChallenge follows RFC 6750 §3: no error code when no token was
// sent, invalid_token when one was rejected.
type bearerChallenge struct{}

func (bearerChallenge) Challenge(err error) string {
	if errors.As(err, new(invalidToken)) {
		return `Bearer error="invalid_token"`
	}
	return "Bearer"
}

// Bearer returns an Authenticator for JWT access tokens in the
// Authorization header (RFC 6750 §2.1). Tokens in the query string or form
// body are not accepted.
func Bearer(v *jwt.Verifier) Authenticator { return jwtBearer{v: v} }

type jwtBearer struct {
	bearerChallenge
	v *jwt.Verifier
}

func (b jwtBearer) AuthenticateRequest(r *http.Request) (authent.Principal, error) {
	token, err := bearerToken(r)
	if err != nil {
		return authent.Principal{}, err
	}
	p, err := b.v.Authenticate(r.Context(), token)
	return p, rejectedToken(err)
}

// APIKey returns an Authenticator for API keys sent as bearer tokens. It
// handles only tokens that start with the Manager's prefix and reports
// ErrNoCredentials for others, so it can precede Bearer in Any.
func APIKey(m *apikey.Manager) Authenticator { return apiKeyBearer{m: m} }

type apiKeyBearer struct {
	bearerChallenge
	m *apikey.Manager
}

func (a apiKeyBearer) AuthenticateRequest(r *http.Request) (authent.Principal, error) {
	token, err := bearerToken(r)
	if err != nil {
		return authent.Principal{}, err
	}
	if !strings.HasPrefix(token, a.m.Prefix()+"_") {
		return authent.Principal{}, ErrNoCredentials
	}
	p, err := a.m.Authenticate(r.Context(), token)
	return p, rejectedToken(err)
}

// DefaultCSRFHeader and DefaultCSRFField are where SessionCookie looks for
// the CSRF token by default.
const (
	DefaultCSRFHeader = "X-CSRF-Token"
	DefaultCSRFField  = "csrf_token"
)

type sessionCookie struct {
	m         *session.Manager
	name      string
	csrfToken func(*http.Request) string
}

// SessionOption configures SessionCookie.
type SessionOption func(*sessionCookie)

// WithCSRFToken sets how the CSRF token is read from a request. Pass nil
// to disable the check, for example when every unsafe request is already
// checked by other means.
func WithCSRFToken(token func(*http.Request) string) SessionOption {
	return func(s *sessionCookie) { s.csrfToken = token }
}

func defaultCSRFToken(r *http.Request) string {
	if t := r.Header.Get(DefaultCSRFHeader); t != "" {
		return t
	}
	return r.PostFormValue(DefaultCSRFField)
}

// SessionCookie returns an Authenticator for session tokens in the cookie
// with the given name. A request with several such cookies is rejected.
//
// Requests with methods other than GET, HEAD, OPTIONS and TRACE must carry
// the session's CSRF token, in the DefaultCSRFHeader header or the
// DefaultCSRFField form field, or they fail with ErrCSRF.
func SessionCookie(m *session.Manager, name string, opts ...SessionOption) Authenticator {
	s := &sessionCookie{m: m, name: name, csrfToken: defaultCSRFToken}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *sessionCookie) AuthenticateRequest(r *http.Request) (authent.Principal, error) {
	cookies := r.CookiesNamed(s.name)
	switch len(cookies) {
	case 0:
		return authent.Principal{}, ErrNoCredentials
	case 1:
	default:
		return authent.Principal{}, fmt.Errorf("%w: several %s cookies", session.ErrInvalidSession, s.name)
	}
	sess, err := s.m.Get(r.Context(), cookies[0].Value)
	if err != nil {
		return authent.Principal{}, err
	}
	if s.csrfToken != nil && !safeMethod(r.Method) && !sess.VerifyCSRF(s.csrfToken(r)) {
		return authent.Principal{}, ErrCSRF
	}
	return sess.Principal(), nil
}

// safeMethod reports whether method is safe per RFC 9110 §9.2.1.
func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

func init() {
	observe.Register(map[error]authent.Reason{
		ErrNoCredentials:   authent.ReasonNoCredentials,
		ErrForbidden:       authent.ReasonForbidden,
		ErrCSRF:            authent.ReasonCSRF,
		errMalformedHeader: authent.ReasonMalformed,
	})
}
