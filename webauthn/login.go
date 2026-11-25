package webauthn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/tohshi/authent"
)

// RequestOptions is PublicKeyCredentialRequestOptionsJSON. Marshal it with
// encoding/json and pass it to
// PublicKeyCredential.parseRequestOptionsFromJSON in the browser.
type RequestOptions struct {
	Challenge        Base64URL              `json:"challenge"`
	Timeout          int64                  `json:"timeout,omitempty"`
	RPID             string                 `json:"rpId"`
	AllowCredentials []CredentialDescriptor `json:"allowCredentials"`
	UserVerification UserVerification       `json:"userVerification"`
}

// BeginLogin starts a login of a known user with one of creds, such as a
// security key used as a second factor after a password. creds must not
// be empty and must all belong to the same user.
func (rp *RelyingParty) BeginLogin(creds []Credential) (RequestOptions, Challenge, error) {
	if len(creds) == 0 {
		return RequestOptions{}, Challenge{}, errors.New("webauthn: no credentials; use BeginDiscoverableLogin for logins without a known user")
	}
	ch, err := rp.newChallenge(ceremonyGet)
	if err != nil {
		return RequestOptions{}, Challenge{}, err
	}
	ch.Subject = creds[0].Subject
	ch.UserHandle = slices.Clone(creds[0].UserHandle)
	if ch.Subject == "" || len(ch.UserHandle) == 0 {
		return RequestOptions{}, Challenge{}, errors.New("webauthn: credential without subject or user handle")
	}
	for _, c := range creds {
		if c.Subject != ch.Subject || !bytes.Equal(c.UserHandle, ch.UserHandle) {
			return RequestOptions{}, Challenge{}, errors.New("webauthn: credentials belong to different users")
		}
		ch.AllowedCredentials = append(ch.AllowedCredentials, slices.Clone(c.ID))
	}
	return rp.requestOptions(ch, descriptors(creds)), ch, nil
}

// BeginDiscoverableLogin starts a login without a known user, where the
// user picks a passkey and the response identifies the account. Consider
// Config.UserVerification = UserVerificationRequired for such logins,
// since the passkey is then the only factor.
func (rp *RelyingParty) BeginDiscoverableLogin() (RequestOptions, Challenge, error) {
	ch, err := rp.newChallenge(ceremonyGet)
	if err != nil {
		return RequestOptions{}, Challenge{}, err
	}
	return rp.requestOptions(ch, []CredentialDescriptor{}), ch, nil
}

func (rp *RelyingParty) requestOptions(ch Challenge, allow []CredentialDescriptor) RequestOptions {
	return RequestOptions{
		Challenge:        ch.Value,
		Timeout:          rp.cfg.Timeout.Milliseconds(),
		RPID:             rp.cfg.RPID,
		AllowCredentials: allow,
		UserVerification: rp.cfg.UserVerification,
	}
}

// authenticationResponse is AuthenticationResponseJSON.
type authenticationResponse struct {
	credentialEnvelope `json:",inline"`
	Response           struct {
		ClientDataJSON    Base64URL `json:"clientDataJSON"`
		AuthenticatorData Base64URL `json:"authenticatorData"`
		Signature         Base64URL `json:"signature"`
		UserHandle        Base64URL `json:"userHandle"`
	} `json:"response"`
}

// FinishLogin verifies the browser's response to the options from
// BeginLogin or BeginDiscoverableLogin (WebAuthn §7.2). On success it
// stores the new signature counter and backup state through
// CredentialStore.UpdateCredential and returns the Principal and the
// updated credential.
//
// Responses that fail verification return an error wrapping
// ErrVerificationFailed. Store failures and unusable stored credentials do
// not wrap authent.ErrUnauthenticated.
func (rp *RelyingParty) FinishLogin(ctx context.Context, ch Challenge, response []byte) (authent.Principal, Credential, error) {
	var r authenticationResponse
	if err := unmarshalResponse(response, &r); err != nil {
		return authent.Principal{}, Credential{}, err
	}
	if err := r.check(); err != nil {
		return authent.Principal{}, Credential{}, err
	}
	cdHash, err := rp.verifyClientData(r.Response.ClientDataJSON, ch, ceremonyGet)
	if err != nil {
		return authent.Principal{}, Credential{}, err
	}
	if len(ch.AllowedCredentials) > 0 && !slices.ContainsFunc(ch.AllowedCredentials, func(id []byte) bool { return bytes.Equal(id, r.RawID) }) {
		return authent.Principal{}, Credential{}, fmt.Errorf("%w: not in allowCredentials", ErrCredentialRejected)
	}

	cred, err := rp.store.LookupCredential(ctx, r.RawID)
	switch {
	case errors.Is(err, ErrCredentialNotFound):
		return authent.Principal{}, Credential{}, fmt.Errorf("%w: unknown credential", ErrCredentialRejected)
	case err != nil:
		return authent.Principal{}, Credential{}, fmt.Errorf("webauthn: looking up credential: %w", err)
	}
	if !bytes.Equal(cred.ID, r.RawID) {
		return authent.Principal{}, Credential{}, errors.New("webauthn: store returned a different credential")
	}

	// The credential must belong to the user the ceremony was started for,
	// or, for discoverable logins, to the user the authenticator names.
	switch {
	case len(ch.UserHandle) > 0 && (!bytes.Equal(cred.UserHandle, ch.UserHandle) || cred.Subject != ch.Subject):
		return authent.Principal{}, Credential{}, fmt.Errorf("%w: credential belongs to another user", ErrCredentialRejected)
	case len(ch.UserHandle) == 0 && len(r.Response.UserHandle) == 0:
		return authent.Principal{}, Credential{}, fmt.Errorf("%w: discoverable login without user handle", ErrCredentialRejected)
	case len(r.Response.UserHandle) > 0 && !bytes.Equal(r.Response.UserHandle, cred.UserHandle):
		return authent.Principal{}, Credential{}, fmt.Errorf("%w: user handle mismatch", ErrCredentialRejected)
	}

	ad, err := parseAuthData(r.Response.AuthenticatorData)
	if err != nil {
		return authent.Principal{}, Credential{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if ad.has(flagAT) {
		return authent.Principal{}, Credential{}, fmt.Errorf("%w: attested credential data in an assertion", ErrMalformed)
	}
	if err := rp.verifyAuthData(ad); err != nil {
		return authent.Principal{}, Credential{}, err
	}

	alg, pub, err := parseCOSEKey(cred.PublicKey)
	if err != nil || alg != cred.Algorithm {
		return authent.Principal{}, Credential{}, fmt.Errorf("webauthn: stored public key of credential %s is unusable: %v", b64.EncodeToString(cred.ID), err)
	}
	if err := verifySignature(alg, pub, append(slices.Clip(ad.raw), cdHash[:]...), r.Response.Signature); err != nil {
		return authent.Principal{}, Credential{}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	if ad.has(flagBE) != cred.BackupEligible {
		return authent.Principal{}, Credential{}, fmt.Errorf("%w: backup eligibility changed", ErrCredentialRejected)
	}
	// WebAuthn §6.1.1: a counter that does not increase signals a possible
	// clone. Authenticators without a counter always report 0.
	if (ad.signCount != 0 || cred.SignCount != 0) && ad.signCount <= cred.SignCount {
		return authent.Principal{}, Credential{}, fmt.Errorf("%w: stored %d, received %d", ErrSignCount, cred.SignCount, ad.signCount)
	}

	cred.SignCount = ad.signCount
	cred.BackupState = ad.has(flagBS)
	switch err := rp.store.UpdateCredential(ctx, cred); {
	case errors.Is(err, ErrSignCount):
		return authent.Principal{}, Credential{}, err
	case err != nil:
		return authent.Principal{}, Credential{}, fmt.Errorf("webauthn: updating credential: %w", err)
	}
	return authent.Principal{
		Subject:  cred.Subject,
		Method:   authent.MethodWebAuthn,
		AuthTime: rp.now(),
		Claims: map[string]any{
			"credential_id": b64.EncodeToString(cred.ID),
			"user_verified": ad.has(flagUV),
		},
	}, cred, nil
}
