package webauthn

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"slices"
)

var oidAndroidKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Android Keymaster values and AuthorizationList tags
// (https://source.android.com/docs/security/features/keystore/attestation).
const (
	kmPurposeSign     = 2
	kmOriginGenerated = 0
	kmTagPurpose      = 1
	kmTagAllApps      = 600
	kmTagOrigin       = 702
)

// Limits of this parser, so that a certificate cannot make it allocate a
// lot of memory.
const (
	maxAuthorizationFields = 128
	maxPurposes            = 16
)

type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TEEEnforced              asn1.RawValue
}

type authorizationList struct {
	purposes        []int
	origins         []int
	allApplications bool
}

// verifyAndroidKey implements WebAuthn §8.4.
func verifyAndroidKey(in attestationInput) (attestationResult, error) {
	a, ok1 := in.stmt.int("alg")
	sig, ok2 := in.stmt.bytes("sig")
	if !ok1 || !ok2 {
		return attestationResult{}, fmt.Errorf("%w: android-key without alg or sig", errAttestation)
	}
	alg := Algorithm(a)
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
	if err := checkCertificateKey(chain[0], in.credKey); err != nil {
		return attestationResult{}, err
	}
	ext, ok := findExtension(chain[0], oidAndroidKeyDescription)
	if !ok {
		return attestationResult{}, fmt.Errorf("%w: android-key certificate without key description", errAttestation)
	}
	kd, lists, err := parseKeyDescription(ext.Value)
	if err != nil {
		return attestationResult{}, err
	}
	if !bytes.Equal(kd.AttestationChallenge, in.clientDataHash) {
		return attestationResult{}, fmt.Errorf("%w: android-key attestation challenge does not match", errAttestation)
	}
	// The union of both lists is checked, which accepts keys outside a
	// TEE, as WebAuthn §8.4 allows.
	var all authorizationList
	for _, l := range lists {
		all.purposes = append(all.purposes, l.purposes...)
		all.origins = append(all.origins, l.origins...)
		all.allApplications = all.allApplications || l.allApplications
	}
	isSign := func(p int) bool { return p == kmPurposeSign }
	isGenerated := func(o int) bool { return o == kmOriginGenerated }
	switch {
	case all.allApplications:
		return attestationResult{}, fmt.Errorf("%w: android-key key is not scoped to the RP ID", errAttestation)
	case len(all.origins) == 0 || !all.allOrigins(isGenerated):
		return attestationResult{}, fmt.Errorf("%w: android-key key was not generated in the keystore", errAttestation)
	case len(all.purposes) == 0 || slices.IndexFunc(all.purposes, func(p int) bool { return !isSign(p) }) >= 0:
		return attestationResult{}, fmt.Errorf("%w: android-key key purpose is not sign", errAttestation)
	}
	return attestationResult{typ: AttestationBasic, chain: chain}, nil
}

func (l authorizationList) allOrigins(f func(int) bool) bool {
	return slices.IndexFunc(l.origins, func(o int) bool { return !f(o) }) < 0
}

func parseKeyDescription(der []byte) (keyDescription, [2]authorizationList, error) {
	var kd keyDescription
	var lists [2]authorizationList
	if rest, err := asn1.Unmarshal(der, &kd); err != nil || len(rest) != 0 {
		return kd, lists, fmt.Errorf("%w: android-key key description: %v", errAttestation, err)
	}
	for i, raw := range []asn1.RawValue{kd.SoftwareEnforced, kd.TEEEnforced} {
		l, err := parseAuthorizationList(raw)
		if err != nil {
			return kd, lists, err
		}
		lists[i] = l
	}
	return kd, lists, nil
}

func parseAuthorizationList(raw asn1.RawValue) (authorizationList, error) {
	var l authorizationList
	fail := func(what string) (authorizationList, error) {
		return authorizationList{}, fmt.Errorf("%w: android-key authorization list: %s", errAttestation, what)
	}
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
		return fail("not a sequence")
	}
	b := raw.Bytes
	for n := 0; len(b) > 0; n++ {
		var field asn1.RawValue
		rest, err := asn1.Unmarshal(b, &field)
		if err != nil || n == maxAuthorizationFields || field.Class != asn1.ClassContextSpecific || !field.IsCompound {
			return fail("invalid field")
		}
		b = rest
		switch field.Tag {
		case kmTagPurpose:
			var purposes []int
			if rest, err := asn1.UnmarshalWithParams(field.Bytes, &purposes, "set"); err != nil || len(rest) != 0 || len(purposes) > maxPurposes {
				return fail("invalid purpose")
			}
			l.purposes = append(l.purposes, purposes...)
		case kmTagOrigin:
			var origin int
			if rest, err := asn1.Unmarshal(field.Bytes, &origin); err != nil || len(rest) != 0 {
				return fail("invalid origin")
			}
			l.origins = append(l.origins, origin)
		case kmTagAllApps:
			l.allApplications = true
		}
	}
	return l, nil
}
