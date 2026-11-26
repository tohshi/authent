package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// JWK is a public JSON Web Key (RFC 7517) or an HMAC secret.
//
// Only public keys are read from and written to JSON. HMAC secrets can be
// used through NewHMACKey but are never parsed from or serialized to JSON.
// Private keys for signing are read with ParsePrivateJWK.
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
	// Certificates is the "x5c" chain, leaf first. ParseJWK checks that
	// the leaf certifies Key; the chain itself is only verified with
	// WithCertificateRoots.
	Certificates []*x509.Certificate
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
	X5C    []string `json:"x5c,omitempty"`

	D   jsontext.Value `json:"d,omitzero"`
	P   jsontext.Value `json:"p,omitzero"`
	Q   jsontext.Value `json:"q,omitzero"`
	DP  jsontext.Value `json:"dp,omitzero"`
	DQ  jsontext.Value `json:"dq,omitzero"`
	QI  jsontext.Value `json:"qi,omitzero"`
	Oth jsontext.Value `json:"oth,omitzero"`
	K   jsontext.Value `json:"k,omitzero"`
}

func (r rawJWK) hasPrivate() bool {
	return slices.ContainsFunc([]jsontext.Value{r.D, r.P, r.Q, r.DP, r.DQ, r.QI, r.Oth, r.K},
		func(v jsontext.Value) bool { return len(v) > 0 })
}

var errUnsupportedKey = errors.New("jwt: unsupported key type")

// ParseJWK parses a single public JWK. Keys with any private or symmetric
// key member are rejected.
func ParseJWK(data []byte) (JWK, error) {
	var r rawJWK
	if err := json.Unmarshal(data, &r); err != nil {
		return JWK{}, fmt.Errorf("jwt: parsing JWK: %w", err)
	}
	return r.toJWK()
}

func (r rawJWK) toJWK() (JWK, error) {
	if r.hasPrivate() {
		return JWK{}, errors.New("jwt: JWK contains private or symmetric key material")
	}
	return r.publicJWK()
}

func (r rawJWK) publicJWK() (JWK, error) {
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
	if k.Certificates, err = parseX5C(r.X5C, k.Key); err != nil {
		return JWK{}, err
	}
	return k, nil
}

func parseX5C(chain []string, key any) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, s := range chain {
		// x5c uses base64 with padding, not base64url.
		der, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil {
			return nil, errors.New("jwt: invalid x5c encoding")
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("jwt: invalid x5c certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) > 0 {
		leaf, ok := certs[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !leaf.Equal(key) {
			return nil, errors.New("jwt: x5c leaf certificate does not match the key")
		}
	}
	return certs, nil
}

func (k JWK) verifyChain(roots *x509.CertPool, now time.Time) error {
	if len(k.Certificates) == 0 {
		return errors.New("no x5c certificate chain")
	}
	leaf := k.Certificates[0]
	intermediates := x509.NewCertPool()
	for _, c := range k.Certificates[1:] {
		intermediates.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		// The default would require the TLS server extended key usage.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return err
	}
	// RFC 5280 §4.2.1.3: without the extension, every usage is allowed.
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("x5c leaf certificate is not for digital signatures")
	}
	return nil
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

// PrivateJWK is a private JSON Web Key used for signing.
type PrivateJWK struct {
	// KeyID is the "kid" parameter.
	KeyID string
	// Algorithm is the "alg" parameter, or empty if the JWK has none.
	Algorithm Algorithm
	// Key is *rsa.PrivateKey, *ecdsa.PrivateKey or ed25519.PrivateKey, as
	// NewSigner accepts.
	Key crypto.Signer
}

// ParsePrivateJWK parses a private RSA, EC (P-256, P-384, P-521) or OKP
// (Ed25519) JWK. The private key must match the public members, and RSA
// keys need all CRT parameters. A "use" other than "sig", "key_ops"
// without "sign", symmetric keys and multi-prime RSA keys are rejected.
// Private keys cannot be marshaled back to JSON.
func ParsePrivateJWK(data []byte) (PrivateJWK, error) {
	var r rawJWK
	if err := json.Unmarshal(data, &r); err != nil {
		return PrivateJWK{}, fmt.Errorf("jwt: parsing JWK: %w", err)
	}
	switch {
	case len(r.K) > 0:
		return PrivateJWK{}, fmt.Errorf("%w: symmetric JWK", errUnsupportedKey)
	case len(r.Oth) > 0:
		return PrivateJWK{}, fmt.Errorf("%w: multi-prime RSA JWK", errUnsupportedKey)
	case len(r.D) == 0:
		return PrivateJWK{}, errors.New("jwt: JWK has no private key")
	case r.Use != "" && r.Use != "sig":
		return PrivateJWK{}, fmt.Errorf("jwt: JWK use %q is not for signing", r.Use)
	case len(r.KeyOps) > 0 && !slices.Contains(r.KeyOps, "sign"):
		return PrivateJWK{}, fmt.Errorf("jwt: JWK key_ops %q do not include sign", r.KeyOps)
	}
	pub, err := r.publicJWK()
	if err != nil {
		return PrivateJWK{}, err
	}
	var priv crypto.Signer
	switch pk := pub.Key.(type) {
	case *rsa.PublicKey:
		priv, err = parseRSAPrivate(r, pk)
	case *ecdsa.PublicKey:
		priv, err = parseECPrivate(r, pk)
	case ed25519.PublicKey:
		priv, err = parseOKPPrivate(r, pk)
	}
	if err != nil {
		return PrivateJWK{}, err
	}
	return PrivateJWK{KeyID: pub.KeyID, Algorithm: pub.Algorithm, Key: priv}, nil
}

func privateParam(v jsontext.Value) ([]byte, error) {
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return nil, err
	}
	b, err := b64.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("invalid base64url value")
	}
	return b, nil
}

func parseRSAPrivate(r rawJWK, pub *rsa.PublicKey) (*rsa.PrivateKey, error) {
	var v [6]*big.Int
	for i, m := range []jsontext.Value{r.D, r.P, r.Q, r.DP, r.DQ, r.QI} {
		if len(m) == 0 {
			return nil, errors.New("jwt: private RSA JWK needs d, p, q, dp, dq and qi")
		}
		b, err := privateParam(m)
		if err != nil {
			return nil, fmt.Errorf("jwt: invalid private RSA JWK: %w", err)
		}
		v[i] = new(big.Int).SetBytes(b)
	}
	priv := &rsa.PrivateKey{
		PublicKey:   *pub,
		D:           v[0],
		Primes:      []*big.Int{v[1], v[2]},
		Precomputed: rsa.PrecomputedValues{Dp: v[3], Dq: v[4], Qinv: v[5]},
	}
	// With the CRT values set, Validate checks n = pq, d, dp, dq and qi
	// against each other.
	priv.Precompute()
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("jwt: invalid private RSA JWK: %w", err)
	}
	return priv, nil
}

func hasRSAPrivateMembers(r rawJWK) bool {
	return len(r.P) > 0 || len(r.Q) > 0 || len(r.DP) > 0 || len(r.DQ) > 0 || len(r.QI) > 0
}

func parseECPrivate(r rawJWK, pub *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	if hasRSAPrivateMembers(r) {
		return nil, errors.New("jwt: invalid private EC JWK: unexpected RSA members")
	}
	d, err := privateParam(r.D)
	// RFC 7518 §6.2.2.1: d MUST be the full size of the curve order.
	if err != nil || len(d) != curveByteSize(pub.Curve) {
		return nil, errors.New("jwt: invalid private EC JWK")
	}
	priv, err := ecdsa.ParseRawPrivateKey(pub.Curve, d)
	if err != nil {
		return nil, fmt.Errorf("jwt: invalid private EC JWK: %w", err)
	}
	if !priv.PublicKey.Equal(pub) {
		return nil, errors.New("jwt: invalid private EC JWK: d does not match x and y")
	}
	return priv, nil
}

func parseOKPPrivate(r rawJWK, pub ed25519.PublicKey) (ed25519.PrivateKey, error) {
	if hasRSAPrivateMembers(r) {
		return nil, errors.New("jwt: invalid private OKP JWK: unexpected RSA members")
	}
	seed, err := privateParam(r.D)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("jwt: invalid private OKP JWK")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !pub.Equal(priv.Public()) {
		return nil, errors.New("jwt: invalid private OKP JWK: d does not match x")
	}
	return priv, nil
}

// MarshalJSON encodes the public key. HMAC keys cannot be marshaled.
func (k JWK) MarshalJSON() ([]byte, error) {
	r, err := k.raw()
	if err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// raw returns the JSON members of a public key.
func (k JWK) raw() (rawJWK, error) {
	r := rawJWK{Kid: k.KeyID, Alg: string(k.Algorithm), Use: k.Use, KeyOps: k.KeyOps}
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		r.Kty = "RSA"
		r.N = b64.EncodeToString(pub.N.Bytes())
		r.E = b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		point, err := pub.Bytes()
		if err != nil {
			return rawJWK{}, fmt.Errorf("jwt: %w", err)
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
		return rawJWK{}, fmt.Errorf("jwt: cannot marshal key of type %T", k.Key)
	}
	for _, c := range k.Certificates {
		r.X5C = append(r.X5C, base64.StdEncoding.EncodeToString(c.Raw))
	}
	return r, nil
}

// Thumbprint returns the JWK Thumbprint (RFC 7638) of the public key,
// computed with h. DPoP (RFC 9449) uses the base64url encoding of the
// SHA-256 thumbprint. HMAC keys have no thumbprint.
func (k JWK) Thumbprint(h crypto.Hash) ([]byte, error) {
	if !h.Available() {
		return nil, fmt.Errorf("jwt: hash %v is not available", h)
	}
	r, err := k.raw()
	if err != nil {
		return nil, err
	}
	// RFC 7638 §3.2: only the required members, in lexicographic order,
	// with no whitespace. The values are base64url strings and curve
	// names, which need no JSON escaping.
	var canonical string
	switch r.Kty {
	case "RSA":
		canonical = `{"e":"` + r.E + `","kty":"RSA","n":"` + r.N + `"}`
	case "EC":
		canonical = `{"crv":"` + r.Crv + `","kty":"EC","x":"` + r.X + `","y":"` + r.Y + `"}`
	case "OKP":
		canonical = `{"crv":"` + r.Crv + `","kty":"OKP","x":"` + r.X + `"}`
	}
	return digest(h, []byte(canonical)), nil
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
