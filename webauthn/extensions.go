package webauthn

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"slices"
)

// ExtensionInputs is AuthenticationExtensionsClientInputsJSON for the
// extensions this package supports. Request them with WithExtensions.
type ExtensionInputs struct {
	// CredProps asks the client whether the new credential is
	// discoverable. Registrations only.
	CredProps bool `json:"credProps,omitzero"`
	// PRF evaluates a pseudo-random function bound to the credential.
	PRF *PRFInputs `json:"prf,omitzero"`
	// LargeBlob asks for large blob storage at registration, and reads or
	// writes the blob at login.
	LargeBlob *LargeBlobInputs `json:"largeBlob,omitzero"`
	// AppID is the https URL that legacy U2F credentials were registered
	// for. Logins only. If the client reports that it used the AppID,
	// FinishLogin expects the AppID's hash instead of the RP ID hash.
	AppID string `json:"appid,omitzero"`
}

// PRFInputs is AuthenticationExtensionsPRFInputsJSON.
type PRFInputs struct {
	// Eval holds the inputs for any credential.
	Eval *PRFValues `json:"eval,omitzero"`
	// EvalByCredential maps base64url credential IDs to the inputs for
	// that credential. Logins started with BeginLogin only, for
	// credentials passed to it.
	EvalByCredential map[string]PRFValues `json:"evalByCredential,omitzero"`
}

// PRFValues is AuthenticationExtensionsPRFValuesJSON: one or two PRF
// inputs, or the 32-byte outputs for them.
type PRFValues struct {
	First  Base64URL `json:"first"`
	Second Base64URL `json:"second,omitzero"`
}

// LargeBlobInputs is AuthenticationExtensionsLargeBlobInputsJSON.
type LargeBlobInputs struct {
	// Support is the requirement at registration. Empty means
	// LargeBlobPreferred. Registrations only.
	Support LargeBlobSupport `json:"support,omitzero"`
	// Read reads the blob. Logins only.
	Read bool `json:"read,omitzero"`
	// Write replaces the blob. Logins with exactly one credential only.
	Write Base64URL `json:"write,omitzero"`
}

// LargeBlobSupport is the large blob requirement of a registration.
type LargeBlobSupport string

const (
	LargeBlobRequired  LargeBlobSupport = "required"
	LargeBlobPreferred LargeBlobSupport = "preferred"
)

// prfOutputSize is the length of every PRF output (WebAuthn L3 §10.1.4).
const prfOutputSize = 32

// check rejects inputs that do not apply to the ceremony or that the
// browser would reject, so that the caller gets the error from Begin.
// allowed is the allowCredentials list of a login.
func (in ExtensionInputs) check(ceremony string, allowed [][]byte) error {
	reg := ceremony == ceremonyCreate
	if in.CredProps && !reg {
		return errors.New("webauthn: credProps applies only to registrations")
	}
	if in.AppID != "" {
		if reg {
			return errors.New("webauthn: appid applies only to logins")
		}
		if u, err := url.Parse(in.AppID); err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("webauthn: appid %q is not an https URL", in.AppID)
		}
	}
	if in.PRF != nil && len(in.PRF.EvalByCredential) > 0 {
		if reg {
			return errors.New("webauthn: prf evalByCredential applies only to logins")
		}
		for id := range in.PRF.EvalByCredential {
			raw, err := decodeB64(id)
			if err != nil || !slices.ContainsFunc(allowed, func(a []byte) bool { return bytes.Equal(a, raw) }) {
				return fmt.Errorf("webauthn: prf evalByCredential key %q is not a credential of this login", id)
			}
		}
	}
	if lb := in.LargeBlob; lb != nil {
		switch {
		case reg && (lb.Read || lb.Write != nil):
			return errors.New("webauthn: largeBlob read and write apply only to logins")
		case reg && lb.Support != "" && lb.Support != LargeBlobRequired && lb.Support != LargeBlobPreferred:
			return fmt.Errorf("webauthn: unknown largeBlob support %q", lb.Support)
		case !reg && lb.Support != "":
			return errors.New("webauthn: largeBlob support applies only to registrations")
		case !reg && lb.Read == (lb.Write != nil):
			return errors.New("webauthn: largeBlob at login needs either read or write")
		case lb.Write != nil && len(allowed) != 1:
			return errors.New("webauthn: largeBlob write needs exactly one credential")
		}
	}
	return nil
}

// ExtensionOutputs holds the outputs of the extensions requested with
// WithExtensions. The browser reports the client outputs, and nothing
// signs them. A nil field means the output was absent.
type ExtensionOutputs struct {
	// Discoverable is credProps.rk: whether the new credential is a
	// discoverable credential.
	Discoverable *bool
	// PRFEnabled is prf.enabled from a registration.
	PRFEnabled *bool
	// PRFResults is prf.results: the PRF outputs for the inputs that
	// applied to the credential.
	PRFResults *PRFValues
	// LargeBlobSupported is largeBlob.supported from a registration.
	LargeBlobSupported *bool
	// LargeBlob is largeBlob.blob, the blob read at login.
	LargeBlob []byte
	// LargeBlobWritten is largeBlob.written from a login.
	LargeBlobWritten *bool
	// AppIDUsed is the appid output: the authenticator signed for
	// ExtensionInputs.AppID.
	AppIDUsed bool
	// Authenticator holds every authenticator extension output in the
	// signed authenticator data, requested or not, keyed by extension
	// identifier. Values are int64, []byte, string, bool, nil, []any or
	// map[any]any.
	Authenticator map[string]any
}

// parseClientOutputs decodes the client outputs of the extensions that ch
// requested, for the credential credID. Outputs of other extensions are
// ignored. An output that the request cannot produce, such as a large blob
// at registration, is rejected.
func parseClientOutputs(raw map[string]jsontext.Value, ch Challenge, credID []byte) (ExtensionOutputs, error) {
	in, reg := ch.Extensions, ch.Ceremony == ceremonyCreate
	var out ExtensionOutputs
	decode := func(id string, v any) error {
		b, ok := raw[id]
		if !ok {
			return nil
		}
		if err := json.Unmarshal(b, v); err != nil {
			return fmt.Errorf("%w: %s extension output: %v", ErrMalformed, id, err)
		}
		return nil
	}
	unexpected := func(output string) error {
		return fmt.Errorf("%w: %s output was not requested", ErrMalformed, output)
	}
	if in.CredProps {
		var o struct {
			RK *bool `json:"rk"`
		}
		if err := decode("credProps", &o); err != nil {
			return ExtensionOutputs{}, err
		}
		out.Discoverable = o.RK
	}
	if in.PRF != nil {
		var o struct {
			Enabled *bool      `json:"enabled"`
			Results *PRFValues `json:"results"`
		}
		if err := decode("prf", &o); err != nil {
			return ExtensionOutputs{}, err
		}
		ev := in.PRF.Eval
		if v, ok := in.PRF.EvalByCredential[b64.EncodeToString(credID)]; ok {
			ev = &v
		}
		switch r := o.Results; {
		case o.Enabled != nil && !reg:
			return ExtensionOutputs{}, unexpected("prf.enabled")
		case r != nil && ev == nil:
			return ExtensionOutputs{}, unexpected("prf.results")
		case r != nil && r.Second != nil && ev.Second == nil:
			return ExtensionOutputs{}, unexpected("prf.results.second")
		case r != nil && (len(r.First) != prfOutputSize || r.Second != nil && len(r.Second) != prfOutputSize):
			return ExtensionOutputs{}, fmt.Errorf("%w: prf results are not %d bytes", ErrMalformed, prfOutputSize)
		}
		out.PRFEnabled, out.PRFResults = o.Enabled, o.Results
	}
	if lb := in.LargeBlob; lb != nil {
		var o struct {
			Supported *bool     `json:"supported"`
			Blob      Base64URL `json:"blob"`
			Written   *bool     `json:"written"`
		}
		if err := decode("largeBlob", &o); err != nil {
			return ExtensionOutputs{}, err
		}
		switch {
		case o.Supported != nil && !reg:
			return ExtensionOutputs{}, unexpected("largeBlob.supported")
		case o.Blob != nil && !lb.Read:
			return ExtensionOutputs{}, unexpected("largeBlob.blob")
		case o.Written != nil && lb.Write == nil:
			return ExtensionOutputs{}, unexpected("largeBlob.written")
		}
		out.LargeBlobSupported, out.LargeBlob, out.LargeBlobWritten = o.Supported, o.Blob, o.Written
	}
	if in.AppID != "" {
		if err := decode("appid", &out.AppIDUsed); err != nil {
			return ExtensionOutputs{}, err
		}
	}
	return out, nil
}

func exportCBOR(v any) any {
	switch v := v.(type) {
	case cborMap:
		m := make(map[any]any, len(v))
		for k, e := range v {
			m[k] = exportCBOR(e)
		}
		return m
	case []any:
		a := make([]any, len(v))
		for i, e := range v {
			a[i] = exportCBOR(e)
		}
		return a
	}
	return v
}
