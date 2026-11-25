package jwt

import (
	"fmt"

	"github.com/tohshi/authent"
)

// ErrInvalidToken is the root of all token rejections. It wraps
// authent.ErrUnauthenticated. The specific errors below wrap it and are
// intended for logs, not for responses to clients.
var ErrInvalidToken = fmt.Errorf("jwt: invalid token: %w", authent.ErrUnauthenticated)

var (
	ErrMalformed            = fmt.Errorf("%w: malformed", ErrInvalidToken)
	ErrUnsupportedAlgorithm = fmt.Errorf("%w: algorithm not allowed", ErrInvalidToken)
	ErrUnsupportedHeader    = fmt.Errorf("%w: unsupported header parameter", ErrInvalidToken)
	ErrUnexpectedType       = fmt.Errorf("%w: unexpected typ", ErrInvalidToken)
	ErrNoMatchingKey        = fmt.Errorf("%w: no matching key", ErrInvalidToken)
	ErrInvalidSignature     = fmt.Errorf("%w: invalid signature", ErrInvalidToken)
	ErrMissingClaim         = fmt.Errorf("%w: missing required claim", ErrInvalidToken)
	ErrExpired              = fmt.Errorf("%w: expired", ErrInvalidToken)
	ErrNotYetValid          = fmt.Errorf("%w: not yet valid", ErrInvalidToken)
	ErrIssuedInFuture       = fmt.Errorf("%w: issued in the future", ErrInvalidToken)
	ErrInvalidIssuer        = fmt.Errorf("%w: issuer not accepted", ErrInvalidToken)
	ErrInvalidAudience      = fmt.Errorf("%w: audience not accepted", ErrInvalidToken)
	// ErrSenderConstrained means the token has a "cnf" claim but the
	// Verifier does not check proof of possession; see
	// WithConfirmationClaim.
	ErrSenderConstrained = fmt.Errorf("%w: sender-constrained token without proof of possession", ErrInvalidToken)
)
