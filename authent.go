// Package authent provides authentication (authn) and authorization (authz)
// building blocks that do not depend on any HTTP framework.
//
// Every authentication method in the sub-packages (password, jwt, session,
// oidc, dpop, totp, webauthn, apikey) produces a [Principal]. Authorization is provided by the rebac
// package, a Zanzibar-style relationship-based access control engine.
//
// The packages depend only on the Go standard library and golang.org/x.
package authent

import (
	"errors"
	"time"
)

// ErrUnauthenticated is the root of all authentication failures. Errors
// returned by the sub-packages for rejected credentials wrap it, so callers
// can map any failure to a single response with errors.Is. The more specific
// errors are meant for logging, not for the response to the client.
var ErrUnauthenticated = errors.New("authent: unauthenticated")

// Method identifies how a Principal was authenticated.
type Method string

const (
	MethodPassword Method = "password"
	MethodJWT      Method = "jwt"
	MethodSession  Method = "session"
	MethodOIDC     Method = "oidc"
	MethodTOTP     Method = "totp"
	MethodHOTP     Method = "hotp"
	MethodWebAuthn Method = "webauthn"
	MethodDPoP     Method = "dpop"
	MethodAPIKey   Method = "apikey"
)

// Principal is an authenticated subject.
type Principal struct {
	// Subject is the stable identifier of the authenticated entity.
	Subject string
	// Issuer identifies who vouched for the subject, such as the "iss" of a
	// token. It is empty for local methods such as password.
	Issuer string
	// Method is how the subject was authenticated.
	Method Method
	// AuthTime is when the subject originally authenticated.
	AuthTime time.Time
	// Claims carries method-specific attributes, such as the JWT claims.
	Claims map[string]any
}
