package authent

import (
	"context"
	"log/slog"
	"time"
)

// Observer receives an Event for every decision of the components it is
// given to with their WithObserver option. Adapt it to logs, metrics or
// traces.
//
// Observe is called synchronously, after the result is decided and
// before it is returned, so it cannot change the result. It must return
// quickly: hand slow work to another goroutine. It may be called from
// many goroutines at once, for example by concurrent requests, CheckBulk
// or the httpauth middleware, so it must be safe for concurrent use. A
// panic in Observe is recovered and discarded, so that an Observer bug
// cannot abort an authentication.
type Observer interface {
	Observe(ctx context.Context, e Event)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(ctx context.Context, e Event)

func (f ObserverFunc) Observe(ctx context.Context, e Event) { f(ctx, e) }

// Event describes one decision. It never carries credentials or values
// derived from them: no passwords, tokens, codes, keys, their hashes, or
// caveat context values. Its fields have a small set of values, so they
// suit metric labels, except Subject.
type Event struct {
	Kind    Kind
	Method  Method
	Outcome Outcome
	// Reason says why a decision was rejected or failed. It is empty on
	// success and for errors without a known cause, such as most store
	// failures.
	Reason Reason
	// Subject is the authenticated subject. It is set only on success.
	Subject string
	// Duration is how long the decision took.
	Duration time.Duration

	// ObjectType and Relation are the object type and the permission of
	// an authorization check.
	ObjectType string
	Relation   string
	// Decision is the result of a successful authorization check.
	Decision Decision
	// Evaluations is the number of relation evaluations of an
	// authorization check, 0 when it was answered from the cache.
	Evaluations int
}

// Kind is the kind of decision an Event describes.
type Kind string

const (
	// KindAuthentication is a credential turned into a Principal.
	KindAuthentication Kind = "authentication"
	// KindTokenVerification is a token verified without producing a
	// Principal, such as jwt.Verifier.Verify or an OIDC logout token.
	KindTokenVerification Kind = "token_verification"
	// KindAuthorization is a rebac permission check.
	KindAuthorization Kind = "authorization"
	// KindHTTPRequest is a decision of the httpauth middleware about a
	// request. It is in addition to the Events of the components the
	// middleware calls.
	KindHTTPRequest Kind = "http_request"
)

// Outcome is how a decision ended.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	// OutcomeRejected means the credentials or the request were refused.
	// The error wraps ErrUnauthenticated, or is httpauth.ErrForbidden.
	OutcomeRejected Outcome = "rejected"
	// OutcomeError means no decision could be made, for example because
	// a store failed.
	OutcomeError Outcome = "error"
)

// Decision is the result of an authorization check.
type Decision string

const (
	DecisionAllowed Decision = "allowed"
	DecisionDenied  Decision = "denied"
	// DecisionConditional means the check depends on caveat parameters
	// that the request did not supply (rebac.ErrMissingContext).
	DecisionConditional Decision = "conditional"
)

// Reason is a stable, machine-readable cause of a rejection or failure.
type Reason string

const (
	// ReasonUnauthenticated is a rejection without a more specific reason.
	ReasonUnauthenticated Reason = "unauthenticated"
	// ReasonInvalidCredentials is a wrong password, key, code or session
	// token, or one that is not known.
	ReasonInvalidCredentials Reason = "invalid_credentials"
	// ReasonUnknownUser is a password login for a user that does not
	// exist. The error returned does not tell it apart from a wrong
	// password.
	ReasonUnknownUser   Reason = "unknown_user"
	ReasonNoCredentials Reason = "no_credentials"
	ReasonMalformed     Reason = "malformed"
	ReasonExpired       Reason = "expired"
	ReasonRevoked       Reason = "revoked"
	ReasonReplayed      Reason = "replayed"
	ReasonNotEnrolled   Reason = "not_enrolled"

	ReasonInvalidToken         Reason = "invalid_token"
	ReasonBadSignature         Reason = "bad_signature"
	ReasonUnsupportedAlgorithm Reason = "unsupported_algorithm"
	ReasonUnsupportedHeader    Reason = "unsupported_header"
	ReasonUnexpectedType       Reason = "unexpected_type"
	ReasonUnknownKey           Reason = "unknown_key"
	ReasonMissingClaim         Reason = "missing_claim"
	ReasonNotYetValid          Reason = "not_yet_valid"
	ReasonTooOld               Reason = "too_old"
	ReasonAuthTooOld           Reason = "auth_too_old"
	ReasonWrongIssuer          Reason = "wrong_issuer"
	ReasonWrongAudience        Reason = "wrong_audience"
	ReasonSenderConstrained    Reason = "sender_constrained"

	ReasonChallengeMismatch Reason = "challenge_mismatch"
	ReasonWrongOrigin       Reason = "wrong_origin"
	ReasonWrongRPID         Reason = "wrong_rp_id"
	ReasonUserNotPresent    Reason = "user_not_present"
	ReasonUserNotVerified   Reason = "user_not_verified"
	// ReasonSignCount is a WebAuthn signature counter that did not
	// increase, a sign of a cloned authenticator.
	ReasonSignCount Reason = "sign_count"

	ReasonInvalidProof  Reason = "invalid_proof"
	ReasonNonceRequired Reason = "nonce_required"
	ReasonKeyMismatch   Reason = "key_mismatch"
	ReasonInactive      Reason = "inactive"

	ReasonStateMismatch    Reason = "state_mismatch"
	ReasonProviderRejected Reason = "provider_rejected"

	ReasonCSRF      Reason = "csrf"
	ReasonForbidden Reason = "forbidden"

	ReasonInvalidInput    Reason = "invalid_input"
	ReasonUnknownRelation Reason = "unknown_relation"
	ReasonTooComplex      Reason = "too_complex"
	ReasonCycle           Reason = "cycle"
	ReasonFutureRevision  Reason = "future_revision"
	ReasonRevisionExpired Reason = "revision_expired"
)

// SlogObserver returns an Observer that logs each Event to l: successes
// at Info, rejections at Warn and errors at Error. Empty fields are left
// out.
func SlogObserver(l *slog.Logger) Observer {
	return ObserverFunc(func(ctx context.Context, e Event) {
		level := slog.LevelInfo
		switch e.Outcome {
		case OutcomeRejected:
			level = slog.LevelWarn
		case OutcomeError:
			level = slog.LevelError
		}
		if !l.Enabled(ctx, level) {
			return
		}
		attrs := make([]slog.Attr, 0, 10)
		for _, a := range []struct{ key, value string }{
			{"kind", string(e.Kind)},
			{"method", string(e.Method)},
			{"outcome", string(e.Outcome)},
			{"reason", string(e.Reason)},
			{"subject", e.Subject},
			{"object_type", e.ObjectType},
			{"relation", e.Relation},
			{"decision", string(e.Decision)},
		} {
			if a.value != "" {
				attrs = append(attrs, slog.String(a.key, a.value))
			}
		}
		attrs = append(attrs, slog.Duration("duration", e.Duration))
		if e.Kind == KindAuthorization {
			attrs = append(attrs, slog.Int("evaluations", e.Evaluations))
		}
		l.LogAttrs(ctx, level, "authent", attrs...)
	})
}
