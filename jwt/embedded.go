package jwt

import (
	"errors"
	"fmt"
	"slices"
)

// EmbeddedKeyJWS is a JWS verified with the public key in its own "jwk"
// header.
type EmbeddedKeyJWS struct {
	Header Header
	// Key is the public key from the "jwk" header.
	Key     JWK
	Payload []byte
}

// VerifyWithEmbeddedKey verifies a compact JWS against the public key in
// its own "jwk" header, as DPoP proofs (RFC 9449) are verified.
//
// A valid result only proves that the signer holds the private key of the
// embedded key. It says nothing about who that is: the caller must check
// that the key is the expected one, for example by comparing its
// Thumbprint with a value bound elsewhere. The payload is not interpreted
// and no claims are checked.
//
// algs must be asymmetric algorithms. The "jwk" header must hold a public
// key that is valid for the token's algorithm; keys with private or
// symmetric key material are rejected. Rejections wrap ErrInvalidToken.
func VerifyWithEmbeddedKey(token string, algs ...Algorithm) (*EmbeddedKeyJWS, error) {
	if len(algs) == 0 {
		return nil, errors.New("jwt: no algorithms given")
	}
	for _, a := range algs {
		if _, ok := a.spec(); !ok || a.IsSymmetric() {
			return nil, fmt.Errorf("jwt: algorithm %q cannot be used with an embedded key", a)
		}
	}
	c, err := parseCompact(token, DefaultMaxTokenSize)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(algs, c.header.Alg) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, c.header.Alg)
	}
	if len(c.header.JWK) == 0 {
		return nil, fmt.Errorf("%w: missing jwk header", ErrMalformed)
	}
	key, err := ParseJWK(c.header.JWK)
	if err != nil {
		return nil, fmt.Errorf("%w: jwk header: %v", ErrMalformed, err)
	}
	if !key.canVerify(c.header.Alg) {
		return nil, fmt.Errorf("%w: jwk header does not match alg %q", ErrNoMatchingKey, c.header.Alg)
	}
	if verify(c.header.Alg, key.Key, []byte(c.signingInput), c.signature) != nil {
		return nil, ErrInvalidSignature
	}
	return &EmbeddedKeyJWS{
		Header:  Header{Algorithm: c.header.Alg, KeyID: c.header.Kid, Type: c.header.Typ},
		Key:     key,
		Payload: c.payload,
	}, nil
}
