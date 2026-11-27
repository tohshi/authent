package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

// AttestationType describes what an attestation statement proved about a
// new credential.
type AttestationType string

const (
	// AttestationNone means no attestation was provided.
	AttestationNone AttestationType = "none"
	// AttestationSelf means the credential signed its own attestation. It
	// proves possession of the key but says nothing about the authenticator.
	AttestationSelf AttestationType = "self"
	// AttestationBasic means an attestation certificate signed the
	// statement. Its trust was checked only if Config.AttestationRoots was
	// set.
	AttestationBasic AttestationType = "basic"
	// AttestationAttCA means a TPM attestation identity key, certified by
	// an attestation CA, signed the statement. Its trust was checked only
	// if Config.AttestationRoots was set.
	AttestationAttCA AttestationType = "attca"
	// AttestationAnonCA means an anonymization CA issued a certificate for
	// the credential key itself, as with Apple devices. Its trust was
	// checked only if Config.AttestationRoots was set.
	AttestationAnonCA AttestationType = "anonca"
)

// maxCertificates bounds the length of an x5c chain.
const maxCertificates = 8

// oidFIDOGenCeAAGUID is id-fido-gen-ce-aaguid.
var oidFIDOGenCeAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

type attestationResult struct {
	typ   AttestationType
	chain []*x509.Certificate // leaf first
}

var errAttestation = errors.New("invalid attestation statement")

type attestationInput struct {
	stmt           cborMap
	ad             *authData
	clientDataHash []byte
	credAlg        Algorithm
	credKey        crypto.PublicKey
}

func (in attestationInput) signed() []byte { return slices.Concat(in.ad.raw, in.clientDataHash) }

var attestationFormats = map[string]func(attestationInput) (attestationResult, error){
	"none":        verifyNone,
	"packed":      verifyPacked,
	"fido-u2f":    verifyFIDOU2F,
	"tpm":         verifyTPM,
	"android-key": verifyAndroidKey,
	"apple":       verifyApple,
}

func verifyAttestation(format string, in attestationInput) (attestationResult, error) {
	verify, ok := attestationFormats[format]
	if !ok {
		return attestationResult{}, fmt.Errorf("%w: unsupported format %q", errAttestation, format)
	}
	return verify(in)
}

func verifyNone(in attestationInput) (attestationResult, error) {
	if len(in.stmt) != 0 {
		return attestationResult{}, fmt.Errorf("%w: none with a non-empty statement", errAttestation)
	}
	return attestationResult{typ: AttestationNone}, nil
}

func verifyPacked(in attestationInput) (attestationResult, error) {
	a, ok1 := in.stmt.int("alg")
	sig, ok2 := in.stmt.bytes("sig")
	if !ok1 || !ok2 {
		return attestationResult{}, fmt.Errorf("%w: packed without alg or sig", errAttestation)
	}
	alg := Algorithm(a)
	if _, ecdaa := in.stmt["ecdaaKeyId"]; ecdaa {
		return attestationResult{}, fmt.Errorf("%w: ECDAA is not supported", errAttestation)
	}
	if _, ok := in.stmt["x5c"]; !ok {
		// Self attestation: the credential key signs.
		if alg != in.credAlg {
			return attestationResult{}, fmt.Errorf("%w: self attestation alg %v differs from the credential's %v", errAttestation, alg, in.credAlg)
		}
		if err := verifySignature(alg, in.credKey, in.signed(), sig); err != nil {
			return attestationResult{}, fmt.Errorf("%w: %v", errAttestation, err)
		}
		return attestationResult{typ: AttestationSelf}, nil
	}
	chain, err := parseX5C(in.stmt)
	if err != nil {
		return attestationResult{}, err
	}
	if !alg.supported() {
		return attestationResult{}, fmt.Errorf("%w: algorithm %v", errAttestation, alg)
	}
	if err := verifySignature(alg, chain[0].PublicKey, in.signed(), sig); err != nil {
		return attestationResult{}, fmt.Errorf("%w: %v", errAttestation, err)
	}
	if err := checkPackedCertificate(chain[0], in.ad.aaguid); err != nil {
		return attestationResult{}, err
	}
	return attestationResult{typ: AttestationBasic, chain: chain}, nil
}

func verifyFIDOU2F(in attestationInput) (attestationResult, error) {
	sig, ok := in.stmt.bytes("sig")
	if !ok {
		return attestationResult{}, fmt.Errorf("%w: fido-u2f without sig", errAttestation)
	}
	chain, err := parseX5C(in.stmt)
	if err != nil {
		return attestationResult{}, err
	}
	if len(chain) != 1 {
		return attestationResult{}, fmt.Errorf("%w: fido-u2f needs exactly one certificate", errAttestation)
	}
	if k, ok := chain[0].PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		return attestationResult{}, fmt.Errorf("%w: fido-u2f certificate key is not P-256", errAttestation)
	}
	ck, ok := in.credKey.(*ecdsa.PublicKey)
	if in.credAlg != ES256 || !ok {
		return attestationResult{}, fmt.Errorf("%w: fido-u2f credential is not ES256", errAttestation)
	}
	point, err := ck.Bytes()
	if err != nil {
		return attestationResult{}, fmt.Errorf("%w: %v", errAttestation, err)
	}
	// WebAuthn §8.6, verification step 5.
	data := slices.Concat([]byte{0}, in.ad.rpIDHash, in.clientDataHash, in.ad.credentialID, point)
	if err := verifySignature(ES256, chain[0].PublicKey, data, sig); err != nil {
		return attestationResult{}, fmt.Errorf("%w: %v", errAttestation, err)
	}
	return attestationResult{typ: AttestationBasic, chain: chain}, nil
}

var oidAppleNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// verifyApple implements WebAuthn §8.8.
func verifyApple(in attestationInput) (attestationResult, error) {
	chain, err := parseX5C(in.stmt)
	if err != nil {
		return attestationResult{}, err
	}
	ext, ok := findExtension(chain[0], oidAppleNonce)
	if !ok {
		return attestationResult{}, fmt.Errorf("%w: apple certificate without nonce extension", errAttestation)
	}
	want := sha256.Sum256(in.signed())
	if nonce, ok := appleNonce(ext.Value); !ok || !bytes.Equal(nonce, want[:]) {
		return attestationResult{}, fmt.Errorf("%w: apple nonce does not match", errAttestation)
	}
	if err := checkCertificateKey(chain[0], in.credKey); err != nil {
		return attestationResult{}, err
	}
	return attestationResult{typ: AttestationAnonCA, chain: chain}, nil
}

func appleNonce(der []byte) ([]byte, bool) {
	var v struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}
	rest, err := asn1.Unmarshal(der, &v)
	return v.Nonce, err == nil && len(rest) == 0
}

func parseX5C(stmt cborMap) ([]*x509.Certificate, error) {
	raw, ok := stmt["x5c"].([]any)
	if !ok || len(raw) == 0 || len(raw) > maxCertificates {
		return nil, fmt.Errorf("%w: invalid x5c", errAttestation)
	}
	chain := make([]*x509.Certificate, 0, len(raw))
	for _, r := range raw {
		der, ok := r.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: x5c entry is not a byte string", errAttestation)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: x5c: %v", errAttestation, err)
		}
		chain = append(chain, c)
	}
	return chain, nil
}

func findExtension(c *x509.Certificate, id asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(id) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

func checkCertificateKey(c *x509.Certificate, credKey crypto.PublicKey) error {
	k, ok := c.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !k.Equal(credKey) {
		return fmt.Errorf("%w: certificate key differs from the credential key", errAttestation)
	}
	return nil
}

func checkAAGUIDExtension(c *x509.Certificate, aaguid [16]byte) error {
	ext, ok := findExtension(c, oidFIDOGenCeAAGUID)
	if !ok {
		return nil
	}
	var v []byte
	rest, err := asn1.Unmarshal(ext.Value, &v)
	if err != nil || len(rest) != 0 || ext.Critical || !bytes.Equal(v, aaguid[:]) {
		return fmt.Errorf("%w: certificate AAGUID extension does not match", errAttestation)
	}
	return nil
}

// checkPackedCertificate applies the requirements of WebAuthn §8.2.1.
func checkPackedCertificate(c *x509.Certificate, aaguid [16]byte) error {
	s := c.Subject
	switch {
	case c.Version != 3:
		return fmt.Errorf("%w: certificate version %d", errAttestation, c.Version)
	case len(s.Country) != 1 || len(s.Organization) != 1 || s.CommonName == "":
		return fmt.Errorf("%w: certificate subject %q lacks C, O or CN", errAttestation, s)
	case !slices.Equal(s.OrganizationalUnit, []string{"Authenticator Attestation"}):
		return fmt.Errorf("%w: certificate OU must be \"Authenticator Attestation\"", errAttestation)
	case c.IsCA:
		return fmt.Errorf("%w: attestation certificate is a CA", errAttestation)
	}
	return checkAAGUIDExtension(c, aaguid)
}
