package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// JWK is a public JSON Web Key (RFC 7517) or an HMAC secret.
//
// Only public keys are read from and written to JSON. HMAC secrets can be
// used through NewHMACKey but are never parsed from or serialized to JSON.
type JWK struct {
	// KeyID is the "kid" parameter.
	KeyID string
	// Algorithm is the "alg" parameter. When set, the key only verifies
	// tokens with exactly this algorithm. When empty, the algorithm is
	// inferred from the key type (and curve for EC keys).
	Algorithm Algorithm
	// Use is the "use" parameter. If set it must be "sig" for the key to be
	// used for verification.
	Use string
	// KeyOps is the "key_ops" parameter. If set it must include "verify"
	// for the key to be used for verification.
	KeyOps []string
	// Key is *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey or, for
	// HMAC, []byte.
	Key any
}

// NewHMACKey returns a JWK holding an HMAC secret for alg (HS256, HS384 or
// HS512). The secret must be at least as long as the hash output.
func NewHMACKey(kid string, alg Algorithm, secret []byte) (JWK, error) {
	if !alg.IsSymmetric() {
		return JWK{}, fmt.Errorf("jwt: %q is not an HMAC algorithm", alg)
	}
	if err := checkVerifyKey(alg, secret); err != nil {
		return JWK{}, fmt.Errorf("jwt: %w", err)
	}
	return JWK{KeyID: kid, Algorithm: alg, Key: slices.Clone(secret)}, nil
}

// canVerify reports whether k may verify a signature made with alg.
func (k JWK) canVerify(alg Algorithm) bool {
	if k.Algorithm != "" && k.Algorithm != alg {
		return false
	}
	if k.Use != "" && k.Use != "sig" {
		return false
	}
	if len(k.KeyOps) > 0 && !slices.Contains(k.KeyOps, "verify") {
		return false
	}
	return checkVerifyKey(alg, k.Key) == nil
}

// rawJWK mirrors the JSON members used by the supported key types.
// encoding/json/v2 matches member names case-sensitively and rejects
// duplicate members.
type rawJWK struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	Use    string   `json:"use,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`

	// Private or symmetric key material. Its presence is an error.
	D jsontext.Value `json:"d,omitzero"`
	K jsontext.Value `json:"k,omitzero"`
}

var errUnsupportedKey = errors.New("jwt: unsupported key type")

// ParseJWK parses a single public JWK. Keys containing private or
// symmetric key material are rejected.
func ParseJWK(data []byte) (JWK, error) {
	var r rawJWK
	if err := json.Unmarshal(data, &r); err != nil {
		return JWK{}, fmt.Errorf("jwt: parsing JWK: %w", err)
	}
	return r.toJWK()
}

func (r rawJWK) toJWK() (JWK, error) {
	if len(r.D) > 0 || len(r.K) > 0 {
		return JWK{}, errors.New("jwt: JWK contains private or symmetric key material")
	}
	k := JWK{KeyID: r.Kid, Algorithm: Algorithm(r.Alg), Use: r.Use, KeyOps: r.KeyOps}
	if k.Algorithm != "" {
		if _, ok := k.Algorithm.spec(); !ok {
			return JWK{}, fmt.Errorf("%w: alg %q", errUnsupportedKey, k.Algorithm)
		}
	}

	var err error
	switch r.Kty {
	case "RSA":
		k.Key, err = parseRSA(r)
	case "EC":
		k.Key, err = parseEC(r)
	case "OKP":
		k.Key, err = parseOKP(r)
	default:
		return JWK{}, fmt.Errorf("%w: kty %q", errUnsupportedKey, r.Kty)
	}
	if err != nil {
		return JWK{}, err
	}
	if k.Algorithm != "" && k.Algorithm.IsSymmetric() {
		return JWK{}, fmt.Errorf("jwt: alg %q does not match kty %q", k.Algorithm, r.Kty)
	}
	if k.Algorithm != "" && checkVerifyKey(k.Algorithm, k.Key) != nil {
		return JWK{}, fmt.Errorf("jwt: alg %q does not match the key", k.Algorithm)
	}
	return k, nil
}

func parseRSA(r rawJWK) (*rsa.PublicKey, error) {
	n, err1 := b64.DecodeString(r.N)
	e, err2 := b64.DecodeString(r.E)
	if err := errors.Join(err1, err2); err != nil || len(n) == 0 || len(e) == 0 {
		return nil, errors.New("jwt: invalid RSA JWK")
	}
	if len(e) > 4 {
		return nil, errors.New("jwt: RSA exponent too large")
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}
	if pub.E < 3 || pub.E%2 == 0 {
		return nil, errors.New("jwt: invalid RSA exponent")
	}
	if pub.N.BitLen() < MinRSABits {
		return nil, fmt.Errorf("jwt: RSA key shorter than %d bits", MinRSABits)
	}
	return pub, nil
}

var curves = map[string]elliptic.Curve{
	"P-256": elliptic.P256(),
	"P-384": elliptic.P384(),
	"P-521": elliptic.P521(),
}

func curveName(c elliptic.Curve) string {
	return c.Params().Name
}

func parseEC(r rawJWK) (*ecdsa.PublicKey, error) {
	curve, ok := curves[r.Crv]
	if !ok {
		return nil, fmt.Errorf("%w: crv %q", errUnsupportedKey, r.Crv)
	}
	x, err1 := b64.DecodeString(r.X)
	y, err2 := b64.DecodeString(r.Y)
	size := curveByteSize(curve)
	// RFC 7518 §6.2.1.2: x and y MUST be the full coordinate size.
	if errors.Join(err1, err2) != nil || len(x) != size || len(y) != size {
		return nil, errors.New("jwt: invalid EC JWK")
	}
	point := append(append([]byte{4}, x...), y...)
	// Rejects points that are not on the curve.
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("jwt: invalid EC JWK: %w", err)
	}
	return pub, nil
}

func parseOKP(r rawJWK) (ed25519.PublicKey, error) {
	if r.Crv != "Ed25519" {
		return nil, fmt.Errorf("%w: crv %q", errUnsupportedKey, r.Crv)
	}
	x, err := b64.DecodeString(r.X)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, errors.New("jwt: invalid OKP JWK")
	}
	return ed25519.PublicKey(x), nil
}

// MarshalJSON encodes the public key. HMAC keys cannot be marshaled.
func (k JWK) MarshalJSON() ([]byte, error) {
	r := rawJWK{Kid: k.KeyID, Alg: string(k.Algorithm), Use: k.Use, KeyOps: k.KeyOps}
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		r.Kty = "RSA"
		r.N = b64.EncodeToString(pub.N.Bytes())
		r.E = b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		point, err := pub.Bytes()
		if err != nil {
			return nil, fmt.Errorf("jwt: %w", err)
		}
		size := curveByteSize(pub.Curve)
		r.Kty = "EC"
		r.Crv = curveName(pub.Curve)
		r.X = b64.EncodeToString(point[1 : 1+size])
		r.Y = b64.EncodeToString(point[1+size:])
	case ed25519.PublicKey:
		r.Kty = "OKP"
		r.Crv = "Ed25519"
		r.X = b64.EncodeToString(pub)
	default:
		return nil, fmt.Errorf("jwt: cannot marshal key of type %T", k.Key)
	}
	return json.Marshal(r)
}

// UnmarshalJSON parses a public JWK; see ParseJWK.
func (k *JWK) UnmarshalJSON(data []byte) error {
	parsed, err := ParseJWK(data)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// JWKSet is a JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// ParseJWKSet parses a JWK Set. Keys that are unsupported or invalid (for
// example encryption keys, or RSA keys below MinRSABits) are skipped, as
// recommended by RFC 7517 §5, so that one odd key published by an identity
// provider does not make the whole set unusable.
func ParseJWKSet(data []byte) (JWKSet, error) {
	var raw struct {
		Keys []rawJWK `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return JWKSet{}, fmt.Errorf("jwt: parsing JWK set: %w", err)
	}
	var set JWKSet
	for _, r := range raw.Keys {
		if k, err := r.toJWK(); err == nil {
			set.Keys = append(set.Keys, k)
		}
	}
	return set, nil
}
