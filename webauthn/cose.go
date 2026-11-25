package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// Algorithm is a COSE algorithm identifier (IANA "COSE Algorithms").
type Algorithm int64

const (
	ES256 Algorithm = -7
	ES384 Algorithm = -35
	ES512 Algorithm = -36
	// EdDSA with Ed25519. Ed448 is not supported.
	EdDSA Algorithm = -8
	RS256 Algorithm = -257
	PS256 Algorithm = -37
)

// MinRSABits is the smallest RSA modulus accepted.
const MinRSABits = 2048

func (a Algorithm) String() string {
	switch a {
	case ES256:
		return "ES256"
	case ES384:
		return "ES384"
	case ES512:
		return "ES512"
	case EdDSA:
		return "EdDSA"
	case RS256:
		return "RS256"
	case PS256:
		return "PS256"
	}
	return fmt.Sprintf("Algorithm(%d)", int64(a))
}

func (a Algorithm) supported() bool {
	switch a {
	case ES256, ES384, ES512, EdDSA, RS256, PS256:
		return true
	}
	return false
}

// COSE key parameters (RFC 9053).
const (
	coseKty = 1
	coseAlg = 3

	coseKtyOKP = 1
	coseKtyEC2 = 2
	coseKtyRSA = 3

	coseCrvP256    = 1
	coseCrvP384    = 2
	coseCrvP521    = 3
	coseCrvEd25519 = 6
)

var errUnsupportedKey = errors.New("unsupported public key")

// parseCOSEKey parses a COSE_Key holding a public key for one of the
// supported algorithms. The key must name its algorithm, and the key type
// and curve must match it.
func parseCOSEKey(data []byte) (Algorithm, crypto.PublicKey, error) {
	v, err := cborDecodeAll(data)
	if err != nil {
		return 0, nil, err
	}
	m, ok := v.(cborMap)
	if !ok {
		return 0, nil, errors.New("COSE key is not a map")
	}
	return coseKeyFromMap(m)
}

func coseKeyFromMap(m cborMap) (Algorithm, crypto.PublicKey, error) {
	kty, ok1 := m.int(int64(coseKty))
	a, ok2 := m.int(int64(coseAlg))
	if !ok1 || !ok2 {
		return 0, nil, errors.New("COSE key without kty or alg")
	}
	alg := Algorithm(a)
	switch kty {
	case coseKtyEC2:
		if _, priv := m[int64(-4)]; priv {
			return 0, nil, errors.New("COSE key contains a private key")
		}
		pub, err := coseEC2(m, alg)
		return alg, pub, err
	case coseKtyOKP:
		if _, priv := m[int64(-4)]; priv {
			return 0, nil, errors.New("COSE key contains a private key")
		}
		crv, _ := m.int(int64(-1))
		x, ok := m.bytes(int64(-2))
		if alg != EdDSA || crv != coseCrvEd25519 || !ok || len(x) != ed25519.PublicKeySize {
			return 0, nil, fmt.Errorf("%w: OKP key for %v", errUnsupportedKey, alg)
		}
		return alg, ed25519.PublicKey(x), nil
	case coseKtyRSA:
		if _, priv := m[int64(-3)]; priv {
			return 0, nil, errors.New("COSE key contains a private key")
		}
		if alg != RS256 && alg != PS256 {
			return 0, nil, fmt.Errorf("%w: RSA key for %v", errUnsupportedKey, alg)
		}
		n, ok1 := m.bytes(int64(-1))
		e, ok2 := m.bytes(int64(-2))
		if !ok1 || !ok2 {
			return 0, nil, errors.New("invalid RSA COSE key")
		}
		pub, err := newRSAKey(n, e)
		return alg, pub, err
	}
	return 0, nil, fmt.Errorf("%w: kty %d", errUnsupportedKey, kty)
}

func coseEC2(m cborMap, alg Algorithm) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	crv, _ := m.int(int64(-1))
	switch {
	case alg == ES256 && crv == coseCrvP256:
		curve = elliptic.P256()
	case alg == ES384 && crv == coseCrvP384:
		curve = elliptic.P384()
	case alg == ES512 && crv == coseCrvP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("%w: EC2 key with crv %d for %v", errUnsupportedKey, crv, alg)
	}
	// y must be the full coordinate; compressed points (a bool) are not
	// accepted.
	x, ok1 := m.bytes(int64(-2))
	y, ok2 := m.bytes(int64(-3))
	size := (curve.Params().BitSize + 7) / 8
	if !ok1 || !ok2 || len(x) != size || len(y) != size {
		return nil, errors.New("invalid EC2 COSE key")
	}
	// Rejects points that are not on the curve.
	return ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
}

func newRSAKey(n, e []byte) (*rsa.PublicKey, error) {
	if len(e) == 0 || len(e) > 4 {
		return nil, errors.New("invalid RSA exponent")
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.E < 3 || pub.E%2 == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	if pub.N.BitLen() < MinRSABits {
		return nil, fmt.Errorf("RSA key shorter than %d bits", MinRSABits)
	}
	return pub, nil
}

var errInvalidSignature = errors.New("signature does not verify")

// verifySignature checks a WebAuthn signature over msg. ECDSA signatures
// are ASN.1 DER encoded, as WebAuthn §6.5.6 specifies. The key type must
// match alg, so that a key is never used with an algorithm chosen by the
// signer.
func verifySignature(alg Algorithm, pub crypto.PublicKey, msg, sig []byte) error {
	switch alg {
	case ES256, ES384, ES512:
		k, ok := pub.(*ecdsa.PublicKey)
		want := map[Algorithm]elliptic.Curve{ES256: elliptic.P256(), ES384: elliptic.P384(), ES512: elliptic.P521()}[alg]
		if !ok || k.Curve != want {
			return fmt.Errorf("%w: %v with %T", errUnsupportedKey, alg, pub)
		}
		var digest []byte
		switch alg {
		case ES256:
			h := sha256.Sum256(msg)
			digest = h[:]
		case ES384:
			h := sha512.Sum384(msg)
			digest = h[:]
		default:
			h := sha512.Sum512(msg)
			digest = h[:]
		}
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errInvalidSignature
		}
		return nil
	case EdDSA:
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %v with %T", errUnsupportedKey, alg, pub)
		}
		if !ed25519.Verify(k, msg, sig) {
			return errInvalidSignature
		}
		return nil
	case RS256, PS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k.N.BitLen() < MinRSABits {
			return fmt.Errorf("%w: %v with %T", errUnsupportedKey, alg, pub)
		}
		h := sha256.Sum256(msg)
		var err error
		if alg == RS256 {
			err = rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig)
		} else {
			err = rsa.VerifyPSS(k, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		if err != nil {
			return errInvalidSignature
		}
		return nil
	}
	return fmt.Errorf("%w: algorithm %v", errUnsupportedKey, alg)
}
