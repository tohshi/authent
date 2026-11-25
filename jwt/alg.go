package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // register SHA-256
	_ "crypto/sha512" // register SHA-384 and SHA-512
	"errors"
	"fmt"
	"math/big"
)

// Algorithm is a JWS "alg" value (RFC 7518 §3, RFC 8037 §3.1).
type Algorithm string

const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	EdDSA Algorithm = "EdDSA"
)

// MinRSABits is the smallest RSA modulus accepted for signing or verifying.
const MinRSABits = 2048

type keyKind int

const (
	kindHMAC keyKind = iota + 1
	kindRSA
	kindRSAPSS
	kindECDSA
	kindEd25519
)

type algSpec struct {
	kind  keyKind
	hash  crypto.Hash
	curve elliptic.Curve // ECDSA only
}

var algSpecs = map[Algorithm]algSpec{
	HS256: {kindHMAC, crypto.SHA256, nil},
	HS384: {kindHMAC, crypto.SHA384, nil},
	HS512: {kindHMAC, crypto.SHA512, nil},
	RS256: {kindRSA, crypto.SHA256, nil},
	RS384: {kindRSA, crypto.SHA384, nil},
	RS512: {kindRSA, crypto.SHA512, nil},
	PS256: {kindRSAPSS, crypto.SHA256, nil},
	PS384: {kindRSAPSS, crypto.SHA384, nil},
	PS512: {kindRSAPSS, crypto.SHA512, nil},
	ES256: {kindECDSA, crypto.SHA256, elliptic.P256()},
	ES384: {kindECDSA, crypto.SHA384, elliptic.P384()},
	ES512: {kindECDSA, crypto.SHA512, elliptic.P521()},
	EdDSA: {kindEd25519, 0, nil},
}

func (a Algorithm) spec() (algSpec, bool) {
	s, ok := algSpecs[a]
	return s, ok
}

// Hash returns the hash function of a, or 0 for EdDSA and unknown values.
func (a Algorithm) Hash() crypto.Hash {
	s, _ := a.spec()
	return s.hash
}

// IsSymmetric reports whether a is an HMAC algorithm.
func (a Algorithm) IsSymmetric() bool {
	s, ok := a.spec()
	return ok && s.kind == kindHMAC
}

var errKeyMismatch = errors.New("key type does not match algorithm")

// checkVerifyKey reports whether key can verify signatures made with alg.
// It is the guard against algorithm confusion: an RSA public key can never
// be used as an HMAC secret, and so on.
func checkVerifyKey(alg Algorithm, key any) error {
	s, ok := alg.spec()
	if !ok {
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
	switch s.kind {
	case kindHMAC:
		k, ok := key.([]byte)
		if !ok {
			return errKeyMismatch
		}
		if len(k) < s.hash.Size() {
			return fmt.Errorf("HMAC key shorter than %d bytes", s.hash.Size())
		}
	case kindRSA, kindRSAPSS:
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return errKeyMismatch
		}
		if k.N.BitLen() < MinRSABits {
			return fmt.Errorf("RSA key shorter than %d bits", MinRSABits)
		}
	case kindECDSA:
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || k.Curve != s.curve {
			return errKeyMismatch
		}
	case kindEd25519:
		k, ok := key.(ed25519.PublicKey)
		if !ok || len(k) != ed25519.PublicKeySize {
			return errKeyMismatch
		}
	}
	return nil
}

// publicKeyOf returns the verification key matching a signing key, or the
// key itself for HMAC.
func publicKeyOf(key any) (any, error) {
	switch k := key.(type) {
	case []byte:
		return k, nil
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported signing key type %T", key)
	}
}

func checkSignKey(alg Algorithm, key any) error {
	pub, err := publicKeyOf(key)
	if err != nil {
		return err
	}
	return checkVerifyKey(alg, pub)
}

func digest(h crypto.Hash, data []byte) []byte {
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil)
}

func sign(alg Algorithm, key any, input []byte) ([]byte, error) {
	if err := checkSignKey(alg, key); err != nil {
		return nil, err
	}
	s, _ := alg.spec()
	switch s.kind {
	case kindHMAC:
		m := hmac.New(s.hash.New, key.([]byte))
		m.Write(input)
		return m.Sum(nil), nil
	case kindRSA:
		return rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), s.hash, digest(s.hash, input))
	case kindRSAPSS:
		return rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), s.hash, digest(s.hash, input),
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case kindECDSA:
		r, ss, err := ecdsa.Sign(rand.Reader, key.(*ecdsa.PrivateKey), digest(s.hash, input))
		if err != nil {
			return nil, err
		}
		n := curveByteSize(s.curve)
		sig := make([]byte, 2*n)
		r.FillBytes(sig[:n])
		ss.FillBytes(sig[n:])
		return sig, nil
	case kindEd25519:
		return ed25519.Sign(key.(ed25519.PrivateKey), input), nil
	}
	return nil, fmt.Errorf("unsupported algorithm %q", alg)
}

var errBadSignature = errors.New("signature verification failed")

func verify(alg Algorithm, key any, input, sig []byte) error {
	if err := checkVerifyKey(alg, key); err != nil {
		return err
	}
	s, _ := alg.spec()
	switch s.kind {
	case kindHMAC:
		m := hmac.New(s.hash.New, key.([]byte))
		m.Write(input)
		if !hmac.Equal(m.Sum(nil), sig) {
			return errBadSignature
		}
	case kindRSA:
		if rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), s.hash, digest(s.hash, input), sig) != nil {
			return errBadSignature
		}
	case kindRSAPSS:
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		if rsa.VerifyPSS(key.(*rsa.PublicKey), s.hash, digest(s.hash, input), sig, opts) != nil {
			return errBadSignature
		}
	case kindECDSA:
		// RFC 7518 §3.4: the signature is the fixed-width concatenation
		// R || S. ASN.1 DER signatures are rejected.
		n := curveByteSize(s.curve)
		if len(sig) != 2*n {
			return errBadSignature
		}
		r := new(big.Int).SetBytes(sig[:n])
		ss := new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(key.(*ecdsa.PublicKey), digest(s.hash, input), r, ss) {
			return errBadSignature
		}
	case kindEd25519:
		if !ed25519.Verify(key.(ed25519.PublicKey), input, sig) {
			return errBadSignature
		}
	}
	return nil
}

func curveByteSize(c elliptic.Curve) int {
	return (c.Params().BitSize + 7) / 8
}
