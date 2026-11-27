package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observe"
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
	Extensions       ExtensionInputs        `json:"extensions,omitzero"`
}

// BeginLogin starts a login of a known user with one of creds, such as a
// security key used as a second factor after a password. creds must not
// be empty and must all belong to the same user.
func (rp *RelyingParty) BeginLogin(creds []Credential, opts ...CeremonyOption) (RequestOptions, Challenge, error) {
	if len(creds) == 0 {
		return RequestOptions{}, Challenge{}, errors.New("webauthn: no credentials; use BeginDiscoverableLogin for logins without a known user")
	}
	subject, handle := creds[0].Subject, creds[0].UserHandle
	if subject == "" || len(handle) == 0 {
		return RequestOptions{}, Challenge{}, errors.New("webauthn: credential without subject or user handle")
	}
	allowed := make([][]byte, 0, len(creds))
	for _, c := range creds {
		if c.Subject != subject || !bytes.Equal(c.UserHandle, handle) {
			return RequestOptions{}, Challenge{}, errors.New("webauthn: credentials belong to different users")
		}
		allowed = append(allowed, slices.Clone(c.ID))
	}
	ch, ext, err := rp.newChallenge(ceremonyGet, allowed, opts)
	if err != nil {
		return RequestOptions{}, Challenge{}, err
	}
	ch.Subject = subject
	ch.UserHandle = slices.Clone(handle)
	return rp.requestOptions(ch, descriptors(creds), ext), ch, nil
}

// BeginDiscoverableLogin starts a login without a known user, where the
// user picks a passkey and the response identifies the account. Consider
// Config.UserVerification = UserVerificationRequired for such logins,
// since the passkey is then the only factor.
func (rp *RelyingParty) BeginDiscoverableLogin(opts ...CeremonyOption) (RequestOptions, Challenge, error) {
	ch, ext, err := rp.newChallenge(ceremonyGet, nil, opts)
	if err != nil {
		return RequestOptions{}, Challenge{}, err
	}
	return rp.requestOptions(ch, []CredentialDescriptor{}, ext), ch, nil
}

func (rp *RelyingParty) requestOptions(ch Challenge, allow []CredentialDescriptor, ext ExtensionInputs) RequestOptions {
	return RequestOptions{
		Challenge:        ch.Value,
		Timeout:          rp.cfg.Timeout.Milliseconds(),
		RPID:             rp.cfg.RPID,
		AllowCredentials: allow,
		UserVerification: rp.cfg.UserVerification,
		Extensions:       ext,
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

// Login is the result of FinishLogin.
type Login struct {
	Principal authent.Principal
	// Credential is the credential with its new signature counter and
	// backup state, already saved with CredentialStore.UpdateCredential.
	Credential Credential
	Extensions ExtensionOutputs
}

// FinishLogin verifies the browser's response to the options from
// BeginLogin or BeginDiscoverableLogin (WebAuthn §7.2). On success it
// stores the new signature counter and backup state through
// CredentialStore.UpdateCredential.
//
// Responses that fail verification return an error wrapping
// ErrVerificationFailed. Store failures and unusable stored credentials do
// not wrap authent.ErrUnauthenticated.
func (rp *RelyingParty) FinishLogin(ctx context.Context, ch Challenge, response []byte) (Login, error) {
	start := observe.Start(rp.observer)
	l, err := rp.finishLogin(ctx, ch, response)
	observe.Done(ctx, rp.observer, authent.KindAuthentication, authent.MethodWebAuthn, start, l.Principal.Subject, err)
	return l, err
}

func (rp *RelyingParty) finishLogin(ctx context.Context, ch Challenge, response []byte) (Login, error) {
	var r authenticationResponse
	if err := unmarshalResponse(response, &r); err != nil {
		return Login{}, err
	}
	if err := r.check(); err != nil {
		return Login{}, err
	}
	cdHash, err := rp.verifyClientData(r.Response.ClientDataJSON, ch, ceremonyGet)
	if err != nil {
		return Login{}, err
	}
	if len(ch.AllowedCredentials) > 0 && !slices.ContainsFunc(ch.AllowedCredentials, func(id []byte) bool { return bytes.Equal(id, r.RawID) }) {
		return Login{}, fmt.Errorf("%w: not in allowCredentials", ErrCredentialRejected)
	}

	cred, err := rp.store.LookupCredential(ctx, r.RawID)
	switch {
	case errors.Is(err, ErrCredentialNotFound):
		return Login{}, fmt.Errorf("%w: unknown credential", ErrCredentialRejected)
	case err != nil:
		return Login{}, fmt.Errorf("webauthn: looking up credential: %w", err)
	}
	if !bytes.Equal(cred.ID, r.RawID) {
		return Login{}, errors.New("webauthn: store returned a different credential")
	}

	// The credential must belong to the user the ceremony was started for,
	// or, for discoverable logins, to the user the authenticator names.
	switch {
	case len(ch.UserHandle) > 0 && (!bytes.Equal(cred.UserHandle, ch.UserHandle) || cred.Subject != ch.Subject):
		return Login{}, fmt.Errorf("%w: credential belongs to another user", ErrCredentialRejected)
	case len(ch.UserHandle) == 0 && len(r.Response.UserHandle) == 0:
		return Login{}, fmt.Errorf("%w: discoverable login without user handle", ErrCredentialRejected)
	case len(r.Response.UserHandle) > 0 && !bytes.Equal(r.Response.UserHandle, cred.UserHandle):
		return Login{}, fmt.Errorf("%w: user handle mismatch", ErrCredentialRejected)
	}

	ad, err := parseAuthData(r.Response.AuthenticatorData)
	if err != nil {
		return Login{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if ad.has(flagAT) {
		return Login{}, fmt.Errorf("%w: attested credential data in an assertion", ErrMalformed)
	}
	ext, err := parseClientOutputs(r.ClientExtensionResults, ch, r.RawID)
	if err != nil {
		return Login{}, err
	}
	rpIDHash := rp.rpIDHash[:]
	if ext.AppIDUsed {
		h := sha256.Sum256([]byte(ch.Extensions.AppID))
		rpIDHash = h[:]
	}
	if err := rp.verifyAuthData(ad, rpIDHash, true); err != nil {
		return Login{}, err
	}

	alg, pub, err := parseCOSEKey(cred.PublicKey)
	if err != nil || alg != cred.Algorithm {
		return Login{}, fmt.Errorf("webauthn: stored public key of credential %s is unusable: %v", b64.EncodeToString(cred.ID), err)
	}
	if err := verifySignature(alg, pub, append(slices.Clip(ad.raw), cdHash[:]...), r.Response.Signature); err != nil {
		return Login{}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	if ad.has(flagBE) != cred.BackupEligible {
		return Login{}, fmt.Errorf("%w: backup eligibility changed", ErrCredentialRejected)
	}
	// WebAuthn §6.1.1: a counter that does not increase signals a possible
	// clone. Authenticators without a counter always report 0.
	if (ad.signCount != 0 || cred.SignCount != 0) && ad.signCount <= cred.SignCount {
		return Login{}, fmt.Errorf("%w: stored %d, received %d", ErrSignCount, cred.SignCount, ad.signCount)
	}

	cred.SignCount = ad.signCount
	cred.BackupState = ad.has(flagBS)
	switch err := rp.store.UpdateCredential(ctx, cred); {
	case errors.Is(err, ErrSignCount):
		return Login{}, err
	case err != nil:
		return Login{}, fmt.Errorf("webauthn: updating credential: %w", err)
	}
	ext.Authenticator = ad.extensions
	return Login{Principal: authent.Principal{
		Subject:  cred.Subject,
		Method:   authent.MethodWebAuthn,
		AuthTime: rp.now(),
		Claims: map[string]any{
			"credential_id": b64.EncodeToString(cred.ID),
			"user_verified": ad.has(flagUV),
		},
	}, Credential: cred, Extensions: ext}, nil
}
