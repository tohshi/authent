// Package jwt signs and verifies JSON Web Tokens in JWS compact
// serialization (RFC 7515, RFC 7519) using only the standard library.
//
// The package deliberately supports a narrow, strict subset:
//
//   - compact serialization only (no JWE, JSON serialization or nested JWTs)
//   - an explicit algorithm allow-list per Verifier; "none" is never accepted
//   - a key is only used with an algorithm matching its type (and its "alg"
//     if set), which prevents algorithm-confusion attacks
//   - headers with "crit" or "b64" are rejected; "jku", "x5u", "jwk" and
//     "x5c" are ignored and never used to find keys by Verifier (only
//     VerifyWithEmbeddedKey, which exists for DPoP proofs, uses "jwk")
//   - JSON is decoded case-sensitively and duplicate members are rejected
package jwt

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
)

var b64 = base64.RawURLEncoding.Strict()

type header struct {
	Alg Algorithm `json:"alg"`
	Kid string    `json:"kid,omitempty"`
	Typ string    `json:"typ,omitempty"`
	// JWK is the "jwk" header. Verifier ignores it; only
	// VerifyWithEmbeddedKey uses it.
	JWK jsontext.Value `json:"jwk,omitzero"`

	// Present only to be rejected.
	Crit jsontext.Value `json:"crit,omitzero"`
	B64  jsontext.Value `json:"b64,omitzero"`
	Zip  jsontext.Value `json:"zip,omitzero"`
	Enc  jsontext.Value `json:"enc,omitzero"`
}

type compact struct {
	header       header
	signingInput string
	payload      []byte
	signature    []byte
}

// DefaultMaxTokenSize is the default upper bound on token length.
const DefaultMaxTokenSize = 16 << 10

func parseCompact(token string, maxSize int) (*compact, error) {
	if len(token) == 0 || len(token) > maxSize {
		return nil, fmt.Errorf("%w: token length %d", ErrMalformed, len(token))
	}
	// The base64 decoder silently skips '\r' and '\n', so the alphabet is
	// checked explicitly to keep exactly one encoding per token.
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.') {
			return nil, fmt.Errorf("%w: invalid character", ErrMalformed)
		}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 segments, got %d", ErrMalformed, len(parts))
	}

	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}

	var h header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	if h.Alg == "" {
		return nil, fmt.Errorf("%w: missing alg", ErrMalformed)
	}
	if len(h.Crit) > 0 || len(h.B64) > 0 || len(h.Zip) > 0 || len(h.Enc) > 0 {
		return nil, ErrUnsupportedHeader
	}

	return &compact{
		header:       h,
		signingInput: parts[0] + "." + parts[1],
		payload:      payload,
		signature:    sig,
	}, nil
}

// Signer creates signed JWTs. It is safe for concurrent use.
type Signer struct {
	alg      Algorithm
	key      any
	kid      string
	typ      string
	embedJWK bool
	jwk      jsontext.Value // the public key, when embedJWK is set
}

// SignerOption configures a Signer.
type SignerOption func(*Signer)

// WithKeyID sets the "kid" header.
func WithKeyID(kid string) SignerOption { return func(s *Signer) { s.kid = kid } }

// WithType sets the "typ" header. The default is "JWT".
func WithType(typ string) SignerOption { return func(s *Signer) { s.typ = typ } }

// WithJWKHeader embeds the public key in the "jwk" header, as DPoP proofs
// (RFC 9449) require. It is only valid for asymmetric algorithms.
func WithJWKHeader() SignerOption { return func(s *Signer) { s.embedJWK = true } }

// NewSigner returns a Signer for alg. key must be []byte for HS*,
// *rsa.PrivateKey for RS*/PS*, *ecdsa.PrivateKey on the matching curve for
// ES*, or ed25519.PrivateKey for EdDSA.
func NewSigner(alg Algorithm, key any, opts ...SignerOption) (*Signer, error) {
	if err := checkSignKey(alg, key); err != nil {
		return nil, fmt.Errorf("jwt: %w", err)
	}
	if b, ok := key.([]byte); ok {
		key = append([]byte(nil), b...)
	}
	s := &Signer{alg: alg, key: key, typ: "JWT"}
	for _, opt := range opts {
		opt(s)
	}
	if s.embedJWK {
		if alg.IsSymmetric() {
			return nil, errors.New("jwt: WithJWKHeader requires an asymmetric algorithm")
		}
		pub, _ := publicKeyOf(key)
		raw, err := json.Marshal(JWK{Key: pub})
		if err != nil {
			return nil, err
		}
		s.jwk = raw
	}
	return s, nil
}

// Sign returns the compact serialization of a JWS over the claims.
func (s *Signer) Sign(c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("jwt: encoding claims: %w", err)
	}
	return s.SignPayload(payload)
}

// SignPayload signs an arbitrary payload. Prefer Sign for JWTs.
func (s *Signer) SignPayload(payload []byte) (string, error) {
	h, err := json.Marshal(header{Alg: s.alg, Kid: s.kid, Typ: s.typ, JWK: s.jwk})
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(payload)
	sig, err := sign(s.alg, s.key, []byte(input))
	if err != nil {
		return "", fmt.Errorf("jwt: signing: %w", err)
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// VerificationKey returns the JWK that verifies this Signer's tokens: the
// public key for asymmetric algorithms, suitable for publishing in a JWK
// Set, or the secret for HMAC.
func (s *Signer) VerificationKey() JWK {
	pub, _ := publicKeyOf(s.key)
	k := JWK{KeyID: s.kid, Algorithm: s.alg, Key: pub}
	if !s.alg.IsSymmetric() {
		k.Use = "sig"
	}
	return k
}
