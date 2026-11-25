package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
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
)

// Attestation statement formats (WebAuthn §8).
const (
	formatNone    = "none"
	formatPacked  = "packed"
	formatFIDOU2F = "fido-u2f"
)

// maxCertificates bounds the length of an x5c chain.
const maxCertificates = 8

// oidFIDOGenCeAAGUID is id-fido-gen-ce-aaguid.
var oidFIDOGenCeAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

type attestationResult struct {
	typ   AttestationType
	chain []*x509.Certificate // leaf first; set for AttestationBasic
}

var errAttestation = errors.New("invalid attestation statement")

// verifyAttestation verifies an attestation statement of a supported format
// over authData and the client data hash. Unsupported formats are rejected.
func verifyAttestation(format string, stmt cborMap, ad *authData, clientDataHash []byte, credAlg Algorithm, credKey crypto.PublicKey) (attestationResult, error) {
	signed := slices.Concat(ad.raw, clientDataHash)
	switch format {
	case formatNone:
		if len(stmt) != 0 {
			return attestationResult{}, fmt.Errorf("%w: none with a non-empty statement", errAttestation)
		}
		return attestationResult{typ: AttestationNone}, nil

	case formatPacked:
		a, ok1 := stmt.int("alg")
		sig, ok2 := stmt.bytes("sig")
		if !ok1 || !ok2 {
			return attestationResult{}, fmt.Errorf("%w: packed without alg or sig", errAttestation)
		}
		alg := Algorithm(a)
		if _, ecdaa := stmt["ecdaaKeyId"]; ecdaa {
			return attestationResult{}, fmt.Errorf("%w: ECDAA is not supported", errAttestation)
		}
		if _, ok := stmt["x5c"]; !ok {
			// Self attestation: the credential key signs.
			if alg != credAlg {
				return attestationResult{}, fmt.Errorf("%w: self attestation alg %v differs from the credential's %v", errAttestation, alg, credAlg)
			}
			if err := verifySignature(alg, credKey, signed, sig); err != nil {
				return attestationResult{}, fmt.Errorf("%w: %v", errAttestation, err)
			}
			return attestationResult{typ: AttestationSelf}, nil
		}
		chain, err := parseX5C(stmt)
		if err != nil {
			return attestationResult{}, err
		}
		if !alg.supported() {
			return attestationResult{}, fmt.Errorf("%w: algorithm %v", errAttestation, alg)
		}
		if err := verifySignature(alg, chain[0].PublicKey, signed, sig); err != nil {
			return attestationResult{}, fmt.Errorf("%w: %v", errAttestation, err)
		}
		if err := checkPackedCertificate(chain[0], ad.aaguid); err != nil {
			return attestationResult{}, err
		}
		return attestationResult{typ: AttestationBasic, chain: chain}, nil

	case formatFIDOU2F:
		sig, ok := stmt.bytes("sig")
		if !ok {
			return attestationResult{}, fmt.Errorf("%w: fido-u2f without sig", errAttestation)
		}
		chain, err := parseX5C(stmt)
		if err != nil {
			return attestationResult{}, err
		}
		if len(chain) != 1 {
			return attestationResult{}, fmt.Errorf("%w: fido-u2f needs exactly one certificate", errAttestation)
		}
		if k, ok := chain[0].PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
			return attestationResult{}, fmt.Errorf("%w: fido-u2f certificate key is not P-256", errAttestation)
		}
		ck, ok := credKey.(*ecdsa.PublicKey)
		if credAlg != ES256 || !ok {
			return attestationResult{}, fmt.Errorf("%w: fido-u2f credential is not ES256", errAttestation)
		}
		point, err := ck.Bytes()
		if err != nil {
			return attestationResult{}, fmt.Errorf("%w: %v", errAttestation, err)
		}
		// WebAuthn §8.6, verification step 5.
		data := slices.Concat([]byte{0}, ad.rpIDHash, clientDataHash, ad.credentialID, point)
		if err := verifySignature(ES256, chain[0].PublicKey, data, sig); err != nil {
			return attestationResult{}, fmt.Errorf("%w: %v", errAttestation, err)
		}
		return attestationResult{typ: AttestationBasic, chain: chain}, nil
	}
	return attestationResult{}, fmt.Errorf("%w: unsupported format %q", errAttestation, format)
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
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidFIDOGenCeAAGUID) {
			continue
		}
		var v []byte
		rest, err := asn1.Unmarshal(ext.Value, &v)
		if err != nil || len(rest) != 0 || ext.Critical || !bytes.Equal(v, aaguid[:]) {
			return fmt.Errorf("%w: certificate AAGUID extension does not match", errAttestation)
		}
	}
	return nil
}
