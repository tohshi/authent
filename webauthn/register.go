package webauthn

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
)

// RPEntity is PublicKeyCredentialRpEntity.
type RPEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserEntity is PublicKeyCredentialUserEntityJSON.
type UserEntity struct {
	ID          Base64URL `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName"`
}

// CredentialParameters is PublicKeyCredentialParameters.
type CredentialParameters struct {
	Type string    `json:"type"`
	Alg  Algorithm `json:"alg"`
}

// AuthenticatorSelection is AuthenticatorSelectionCriteria.
type AuthenticatorSelection struct {
	ResidentKey        ResidentKey      `json:"residentKey"`
	RequireResidentKey bool             `json:"requireResidentKey"`
	UserVerification   UserVerification `json:"userVerification"`
}

// CreationOptions is PublicKeyCredentialCreationOptionsJSON. Marshal it
// with encoding/json and pass it to
// PublicKeyCredential.parseCreationOptionsFromJSON in the browser.
type CreationOptions struct {
	RP                     RPEntity               `json:"rp"`
	User                   UserEntity             `json:"user"`
	Challenge              Base64URL              `json:"challenge"`
	PubKeyCredParams       []CredentialParameters `json:"pubKeyCredParams"`
	Timeout                int64                  `json:"timeout,omitempty"`
	ExcludeCredentials     []CredentialDescriptor `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	Attestation            Conveyance             `json:"attestation"`
	Extensions             ExtensionInputs        `json:"extensions,omitzero"`
}

// BeginRegistration starts registering a new credential for user. Pass
// the user's existing credentials as exclude, so that an authenticator
// that already holds one of them is not registered twice.
func (rp *RelyingParty) BeginRegistration(user User, exclude []Credential, opts ...CeremonyOption) (CreationOptions, Challenge, error) {
	if user.Subject == "" {
		return CreationOptions{}, Challenge{}, errors.New("webauthn: user subject is required")
	}
	if len(user.Handle) == 0 || len(user.Handle) > 64 {
		return CreationOptions{}, Challenge{}, errors.New("webauthn: user handle must be 1 to 64 bytes")
	}
	if user.Name == "" {
		return CreationOptions{}, Challenge{}, errors.New("webauthn: user name is required")
	}
	ch, ext, err := rp.newChallenge(ceremonyCreate, nil, opts)
	if err != nil {
		return CreationOptions{}, Challenge{}, err
	}
	ch.Subject = user.Subject
	ch.UserHandle = slices.Clone(user.Handle)

	params := make([]CredentialParameters, 0, len(rp.cfg.Algorithms))
	for _, a := range rp.cfg.Algorithms {
		params = append(params, CredentialParameters{Type: "public-key", Alg: a})
	}
	options := CreationOptions{
		RP:                 RPEntity{ID: rp.cfg.RPID, Name: rp.cfg.RPName},
		User:               UserEntity{ID: ch.UserHandle, Name: user.Name, DisplayName: user.DisplayName},
		Challenge:          ch.Value,
		PubKeyCredParams:   params,
		Timeout:            rp.cfg.Timeout.Milliseconds(),
		ExcludeCredentials: descriptors(exclude),
		AuthenticatorSelection: AuthenticatorSelection{
			ResidentKey:        rp.cfg.ResidentKey,
			RequireResidentKey: rp.cfg.ResidentKey == ResidentKeyRequired,
			UserVerification:   rp.cfg.UserVerification,
		},
		Attestation: rp.cfg.Attestation,
		Extensions:  ext,
	}
	return options, ch, nil
}

// registrationResponse is RegistrationResponseJSON.
type registrationResponse struct {
	credentialEnvelope `json:",inline"`
	Response           struct {
		ClientDataJSON    Base64URL `json:"clientDataJSON"`
		AttestationObject Base64URL `json:"attestationObject"`
		Transports        []string  `json:"transports"`
	} `json:"response"`
}

var knownTransports = []string{"ble", "hybrid", "internal", "nfc", "smart-card", "usb"}

// Registration is the result of FinishRegistration.
type Registration struct {
	// Credential is the new credential. The caller stores it for
	// Challenge.Subject.
	Credential Credential
	Extensions ExtensionOutputs
}

// FinishRegistration verifies the browser's response to the options from
// BeginRegistration (WebAuthn §7.1). Responses that fail verification
// return an error wrapping ErrVerificationFailed.
func (rp *RelyingParty) FinishRegistration(ctx context.Context, ch Challenge, response []byte) (Registration, error) {
	var r registrationResponse
	if err := unmarshalResponse(response, &r); err != nil {
		return Registration{}, err
	}
	if err := r.check(); err != nil {
		return Registration{}, err
	}
	if ch.Subject == "" || len(ch.UserHandle) == 0 {
		return Registration{}, fmt.Errorf("%w: challenge has no user", ErrChallenge)
	}
	cdHash, err := rp.verifyClientData(r.Response.ClientDataJSON, ch, ceremonyCreate)
	if err != nil {
		return Registration{}, err
	}
	ext, err := parseClientOutputs(r.ClientExtensionResults, ch)
	if err != nil {
		return Registration{}, err
	}

	v, err := cborDecodeAll(r.Response.AttestationObject)
	if err != nil {
		return Registration{}, fmt.Errorf("%w: attestation object: %v", ErrMalformed, err)
	}
	obj, _ := v.(cborMap)
	format, ok1 := obj.text("fmt")
	rawAuthData, ok2 := obj.bytes("authData")
	stmt, ok3 := obj["attStmt"].(cborMap)
	if !ok1 || !ok2 || !ok3 {
		return Registration{}, fmt.Errorf("%w: attestation object lacks fmt, authData or attStmt", ErrMalformed)
	}
	ad, err := parseAuthData(rawAuthData)
	if err != nil {
		return Registration{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := rp.verifyAuthData(ad, rp.rpIDHash[:], !ch.Conditional); err != nil {
		return Registration{}, err
	}
	if !ad.has(flagAT) {
		return Registration{}, fmt.Errorf("%w: no attested credential data", ErrMalformed)
	}
	if !bytes.Equal(ad.credentialID, r.RawID) {
		return Registration{}, fmt.Errorf("%w: credential ID differs from rawId", ErrMalformed)
	}
	alg, pub, err := parseCOSEKey(ad.publicKey)
	if err != nil {
		return Registration{}, fmt.Errorf("%w: credential public key: %v", ErrAlgorithm, err)
	}
	if !slices.Contains(rp.cfg.Algorithms, alg) {
		return Registration{}, fmt.Errorf("%w: %v", ErrAlgorithm, alg)
	}

	att, err := verifyAttestation(format, stmt, ad, cdHash[:], alg, pub)
	if err != nil {
		return Registration{}, fmt.Errorf("%w: %v", ErrAttestation, err)
	}
	if err := rp.trustAttestation(att); err != nil {
		return Registration{}, err
	}

	switch _, err := rp.store.LookupCredential(ctx, ad.credentialID); {
	case err == nil:
		return Registration{}, ErrCredentialExists
	case !errors.Is(err, ErrCredentialNotFound):
		return Registration{}, fmt.Errorf("webauthn: looking up credential: %w", err)
	}

	var transports []string
	for _, t := range r.Response.Transports {
		if slices.Contains(knownTransports, t) && !slices.Contains(transports, t) {
			transports = append(transports, t)
		}
	}
	ext.Authenticator = ad.extensions
	return Registration{Credential: Credential{
		ID:                slices.Clone(ad.credentialID),
		Subject:           ch.Subject,
		UserHandle:        slices.Clone(ch.UserHandle),
		PublicKey:         slices.Clone(ad.publicKey),
		Algorithm:         alg,
		SignCount:         ad.signCount,
		Transports:        transports,
		AAGUID:            ad.aaguid,
		BackupEligible:    ad.has(flagBE),
		BackupState:       ad.has(flagBS),
		UserVerified:      ad.has(flagUV),
		AttestationFormat: format,
		AttestationType:   att.typ,
	}, Extensions: ext}, nil
}

// trustAttestation enforces Config.AttestationRoots.
func (rp *RelyingParty) trustAttestation(att attestationResult) error {
	if rp.cfg.AttestationRoots == nil {
		return nil
	}
	if att.typ != AttestationBasic || len(att.chain) == 0 {
		return fmt.Errorf("%w: %s attestation is not trusted", ErrAttestation, att.typ)
	}
	inter := x509.NewCertPool()
	for _, c := range att.chain[1:] {
		inter.AddCert(c)
	}
	_, err := att.chain[0].Verify(x509.VerifyOptions{
		Roots:         rp.cfg.AttestationRoots,
		Intermediates: inter,
		CurrentTime:   rp.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAttestation, err)
	}
	return nil
}
