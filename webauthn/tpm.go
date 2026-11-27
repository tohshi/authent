package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"slices"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// TPM 2.0 constants (TPM 2.0 Library, Part 2).
const (
	tpmGeneratedValue     = 0xff544347
	tpmSTAttestCertify    = 0x8017
	tpmAlgRSA             = 0x0001
	tpmAlgSHA1            = 0x0004
	tpmAlgSHA256          = 0x000b
	tpmAlgSHA384          = 0x000c
	tpmAlgSHA512          = 0x000d
	tpmAlgNull            = 0x0010
	tpmAlgECC             = 0x0023
	tpmECCNistP256        = 0x0003
	tpmECCNistP384        = 0x0004
	tpmECCNistP521        = 0x0005
	tpmRSADefaultExponent = 65537

	tpmClockInfoSize       = 17 // TPMS_CLOCK_INFO
	tpmFirmwareVersionSize = 8
)

// rs1 is RSASSA-PKCS1-v1_5 with SHA-1. RFC 8812 (§2, §5.3) registers it
// in the IANA COSE Algorithms registry as deprecated, only because
// deployed TPMs still sign attestations with it. It is accepted for TPM
// statements, never for credentials.
const rs1 Algorithm = -65535

var (
	oidTCGKpAIKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
	oidTPMManufacturer     = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel            = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion          = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	oidSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}

	sanDirectoryName = cbasn1.Tag(4).ContextSpecific().Constructed()
)

// verifyTPM implements WebAuthn §8.3.
func verifyTPM(in attestationInput) (attestationResult, error) {
	ver, _ := in.stmt.text("ver")
	a, ok1 := in.stmt.int("alg")
	sig, ok2 := in.stmt.bytes("sig")
	certInfo, ok3 := in.stmt.bytes("certInfo")
	pubArea, ok4 := in.stmt.bytes("pubArea")
	if ver != "2.0" || !ok1 || !ok2 || !ok3 || !ok4 {
		return attestationResult{}, fmt.Errorf("%w: tpm statement lacks ver 2.0, alg, sig, certInfo or pubArea", errAttestation)
	}
	if _, ecdaa := in.stmt["ecdaaKeyId"]; ecdaa {
		return attestationResult{}, fmt.Errorf("%w: ECDAA is not supported", errAttestation)
	}
	alg := Algorithm(a)
	h, ok := tpmSignatureHash(alg)
	if !ok {
		return attestationResult{}, fmt.Errorf("%w: tpm algorithm %v", errAttestation, alg)
	}

	nameAlg, pub, err := parseTPMPublic(pubArea)
	if err != nil {
		return attestationResult{}, err
	}
	if k, ok := pub.(interface{ Equal(crypto.PublicKey) bool }); !ok || !k.Equal(in.credKey) {
		return attestationResult{}, fmt.Errorf("%w: tpm pubArea differs from the credential key", errAttestation)
	}
	extraData, name, err := parseTPMCertifyInfo(certInfo)
	if err != nil {
		return attestationResult{}, err
	}
	if d := h.New(); !bytes.Equal(extraData, sum(d, in.signed())) {
		return attestationResult{}, fmt.Errorf("%w: tpm extraData does not match", errAttestation)
	}
	if want, ok := tpmName(nameAlg, pubArea); !ok || !bytes.Equal(name, want) {
		return attestationResult{}, fmt.Errorf("%w: tpm certInfo does not certify pubArea", errAttestation)
	}

	chain, err := parseX5C(in.stmt)
	if err != nil {
		return attestationResult{}, err
	}
	if err := checkTPMCertificate(chain[0], in.ad.aaguid); err != nil {
		return attestationResult{}, err
	}
	if err := verifyTPMSignature(alg, chain[0].PublicKey, certInfo, sig); err != nil {
		return attestationResult{}, fmt.Errorf("%w: %v", errAttestation, err)
	}
	return attestationResult{typ: AttestationAttCA, chain: chain}, nil
}

func tpmSignatureHash(alg Algorithm) (crypto.Hash, bool) {
	switch alg {
	case rs1:
		return crypto.SHA1, true
	case ES256, RS256, PS256:
		return crypto.SHA256, true
	case ES384:
		return crypto.SHA384, true
	case ES512:
		return crypto.SHA512, true
	}
	return 0, false
}

func verifyTPMSignature(alg Algorithm, pub crypto.PublicKey, msg, sig []byte) error {
	if alg != rs1 {
		return verifySignature(alg, pub, msg, sig)
	}
	k, ok := pub.(*rsa.PublicKey)
	if !ok || k.N.BitLen() < MinRSABits {
		return fmt.Errorf("%w: %v with %T", errUnsupportedKey, alg, pub)
	}
	h := sha1.Sum(msg)
	if rsa.VerifyPKCS1v15(k, crypto.SHA1, h[:], sig) != nil {
		return errInvalidSignature
	}
	return nil
}

func sum(h hash.Hash, b []byte) []byte {
	h.Write(b)
	return h.Sum(nil)
}

func tpmName(nameAlg uint16, pubArea []byte) ([]byte, bool) {
	var h hash.Hash
	switch nameAlg {
	case tpmAlgSHA256:
		h = sha256.New()
	case tpmAlgSHA384:
		h = sha512.New384()
	case tpmAlgSHA512:
		h = sha512.New()
	default:
		return nil, false
	}
	return append([]byte{byte(nameAlg >> 8), byte(nameAlg)}, sum(h, pubArea)...), true
}

func parseTPMPublic(b []byte) (uint16, crypto.PublicKey, error) {
	fail := func(what string) (uint16, crypto.PublicKey, error) {
		return 0, nil, fmt.Errorf("%w: tpm pubArea: %s", errAttestation, what)
	}
	s := cryptobyte.String(b)
	var typ, nameAlg, symmetric uint16
	var attributes uint32
	var authPolicy cryptobyte.String
	if !s.ReadUint16(&typ) || !s.ReadUint16(&nameAlg) || !s.ReadUint32(&attributes) ||
		!s.ReadUint16LengthPrefixed(&authPolicy) || !s.ReadUint16(&symmetric) {
		return fail("truncated")
	}
	if symmetric != tpmAlgNull {
		return fail("symmetric algorithm on a signing key")
	}
	if !skipTPMScheme(&s) {
		return fail("truncated scheme")
	}
	var pub crypto.PublicKey
	switch typ {
	case tpmAlgRSA:
		var bits uint16
		var exponent uint32
		var n cryptobyte.String
		if !s.ReadUint16(&bits) || !s.ReadUint32(&exponent) || !s.ReadUint16LengthPrefixed(&n) {
			return fail("truncated RSA key")
		}
		if exponent == 0 {
			exponent = tpmRSADefaultExponent
		}
		k, err := newRSAKey(n, []byte{byte(exponent >> 24), byte(exponent >> 16), byte(exponent >> 8), byte(exponent)})
		if err != nil || k.N.BitLen() != int(bits) {
			return fail("invalid RSA key")
		}
		pub = k
	case tpmAlgECC:
		var curveID uint16
		var x, y cryptobyte.String
		if !s.ReadUint16(&curveID) || !skipTPMScheme(&s) || !s.ReadUint16LengthPrefixed(&x) || !s.ReadUint16LengthPrefixed(&y) {
			return fail("truncated ECC key")
		}
		curve, ok := map[uint16]elliptic.Curve{tpmECCNistP256: elliptic.P256(), tpmECCNistP384: elliptic.P384(), tpmECCNistP521: elliptic.P521()}[curveID]
		size := 0
		if ok {
			size = (curve.Params().BitSize + 7) / 8
		}
		if !ok || len(x) != size || len(y) != size {
			return fail("unsupported ECC key")
		}
		k, err := ecdsa.ParseUncompressedPublicKey(curve, slices.Concat([]byte{4}, x, y))
		if err != nil {
			return fail("invalid ECC key")
		}
		pub = k
	default:
		return fail(fmt.Sprintf("key type %#x", typ))
	}
	if !s.Empty() {
		return fail("trailing bytes")
	}
	return nameAlg, pub, nil
}

func skipTPMScheme(s *cryptobyte.String) bool {
	var alg, hashAlg uint16
	if !s.ReadUint16(&alg) {
		return false
	}
	return alg == tpmAlgNull || s.ReadUint16(&hashAlg)
}

func parseTPMCertifyInfo(b []byte) (extraData, name []byte, err error) {
	s := cryptobyte.String(b)
	var magic uint32
	var typ uint16
	var signer, data, n, qualifiedName cryptobyte.String
	if !s.ReadUint32(&magic) || !s.ReadUint16(&typ) || !s.ReadUint16LengthPrefixed(&signer) || !s.ReadUint16LengthPrefixed(&data) ||
		!s.Skip(tpmClockInfoSize+tpmFirmwareVersionSize) ||
		!s.ReadUint16LengthPrefixed(&n) || !s.ReadUint16LengthPrefixed(&qualifiedName) || !s.Empty() {
		return nil, nil, fmt.Errorf("%w: malformed tpm certInfo", errAttestation)
	}
	if magic != tpmGeneratedValue || typ != tpmSTAttestCertify {
		return nil, nil, fmt.Errorf("%w: tpm certInfo is not a TPM-generated certification", errAttestation)
	}
	return data, n, nil
}

// checkTPMCertificate applies the requirements of WebAuthn §8.3.1 to the
// AIK certificate.
func checkTPMCertificate(c *x509.Certificate, aaguid [16]byte) error {
	switch {
	case c.Version != 3:
		return fmt.Errorf("%w: AIK certificate version %d", errAttestation, c.Version)
	case !bytes.Equal(c.RawSubject, []byte{0x30, 0}):
		return fmt.Errorf("%w: AIK certificate subject is not empty", errAttestation)
	case !slices.ContainsFunc(c.UnknownExtKeyUsage, oidTCGKpAIKCertificate.Equal):
		return fmt.Errorf("%w: AIK certificate lacks the tcg-kp-AIKCertificate key usage", errAttestation)
	case !c.BasicConstraintsValid || c.IsCA:
		return fmt.Errorf("%w: AIK certificate is not marked as a non-CA", errAttestation)
	}
	san, ok := findExtension(c, oidSubjectAltName)
	if !ok || !hasTPMDeviceAttributes(san.Value) {
		return fmt.Errorf("%w: AIK certificate lacks the TPM subject alternative name", errAttestation)
	}
	// The SAN holds only a directoryName, which crypto/x509 leaves to the
	// caller; it has been checked above, so chain verification may accept it.
	c.UnhandledCriticalExtensions = slices.DeleteFunc(c.UnhandledCriticalExtensions, oidSubjectAltName.Equal)
	return checkAAGUIDExtension(c, aaguid)
}

func hasTPMDeviceAttributes(san []byte) bool {
	s := cryptobyte.String(san)
	var names cryptobyte.String
	if !s.ReadASN1(&names, cbasn1.SEQUENCE) || !s.Empty() {
		return false
	}
	found := map[string]bool{}
	for !names.Empty() {
		var name cryptobyte.String
		var tag cbasn1.Tag
		if !names.ReadAnyASN1(&name, &tag) {
			return false
		}
		if tag != sanDirectoryName {
			continue
		}
		var rdns pkix.RDNSequence
		if rest, err := asn1.Unmarshal(name, &rdns); err != nil || len(rest) != 0 {
			return false
		}
		for _, rdn := range rdns {
			for _, atv := range rdn {
				if _, ok := atv.Value.(string); ok {
					found[atv.Type.String()] = true
				}
			}
		}
	}
	return found[oidTPMManufacturer.String()] && found[oidTPMModel.String()] && found[oidTPMVersion.String()]
}
