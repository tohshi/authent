// Package webauthn implements the relying party side of Web Authentication
// (WebAuthn Level 3): registering credentials and verifying assertions,
// for passkeys and for security keys used as a second factor.
//
// Each ceremony has two steps. Begin returns options for the browser and a
// Challenge. Send the options to the browser as JSON and pass them to
// PublicKeyCredential.parseCreationOptionsFromJSON or
// parseRequestOptionsFromJSON. Keep the Challenge server-side, for example
// JSON-encoded in a session value, and delete it once it has been used.
// Finish takes the Challenge and the JSON of the browser's
// PublicKeyCredential (credential.toJSON()).
//
// The package depends only on the standard library. CBOR and COSE are
// decoded here.
package webauthn

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/tohshi/authent"
)

// ErrVerificationFailed is the root of all rejected registration and
// authentication responses. It wraps authent.ErrUnauthenticated. The
// specific errors below wrap it and are intended for logs, not for
// responses to clients.
var ErrVerificationFailed = fmt.Errorf("webauthn: verification failed: %w", authent.ErrUnauthenticated)

var (
	ErrMalformed          = fmt.Errorf("%w: malformed response", ErrVerificationFailed)
	ErrChallenge          = fmt.Errorf("%w: challenge mismatch or expired", ErrVerificationFailed)
	ErrOrigin             = fmt.Errorf("%w: origin not allowed", ErrVerificationFailed)
	ErrRPID               = fmt.Errorf("%w: RP ID hash mismatch", ErrVerificationFailed)
	ErrUserNotPresent     = fmt.Errorf("%w: user not present", ErrVerificationFailed)
	ErrUserNotVerified    = fmt.Errorf("%w: user not verified", ErrVerificationFailed)
	ErrAlgorithm          = fmt.Errorf("%w: algorithm not allowed", ErrVerificationFailed)
	ErrAttestation        = fmt.Errorf("%w: attestation not accepted", ErrVerificationFailed)
	ErrInvalidSignature   = fmt.Errorf("%w: invalid signature", ErrVerificationFailed)
	ErrCredentialRejected = fmt.Errorf("%w: credential not allowed for this ceremony", ErrVerificationFailed)
	// ErrSignCount means the signature counter did not increase, which
	// suggests the authenticator was cloned.
	ErrSignCount = fmt.Errorf("%w: signature counter did not increase", ErrVerificationFailed)
	// ErrCredentialExists is returned by FinishRegistration when the
	// credential ID is already registered.
	ErrCredentialExists = fmt.Errorf("%w: credential already registered", ErrVerificationFailed)
)

// ErrCredentialNotFound must be returned by CredentialStore.LookupCredential
// for unknown credential IDs.
var ErrCredentialNotFound = errors.New("webauthn: credential not found")

// UserVerification is the user verification requirement.
type UserVerification string

const (
	// UserVerificationRequired rejects responses without the UV flag. Use it
	// for passkeys used as the only factor.
	UserVerificationRequired UserVerification = "required"
	// UserVerificationPreferred asks for user verification but accepts
	// responses without it. Principal.Claims["user_verified"] reports the
	// result.
	UserVerificationPreferred UserVerification = "preferred"
	// UserVerificationDiscouraged suits security keys used as a second
	// factor after a password.
	UserVerificationDiscouraged UserVerification = "discouraged"
)

// ResidentKey is the discoverable credential requirement.
type ResidentKey string

const (
	ResidentKeyRequired    ResidentKey = "required"
	ResidentKeyPreferred   ResidentKey = "preferred"
	ResidentKeyDiscouraged ResidentKey = "discouraged"
)

// Conveyance is the attestation conveyance preference.
type Conveyance string

const (
	ConveyanceNone     Conveyance = "none"
	ConveyanceIndirect Conveyance = "indirect"
	ConveyanceDirect   Conveyance = "direct"
)

// Config configures a RelyingParty.
type Config struct {
	// RPID is the relying party ID, a registrable domain such as
	// "example.com". Credentials are bound to it.
	RPID string
	// RPName is shown to the user during registration.
	RPName string
	// Origins lists the accepted origins, such as "https://example.com" or
	// "https://login.example.com". Each web origin must use https, except
	// http://localhost for development, and its host must be RPID or a
	// subdomain of it. An Android app is listed as "android:apk-key-hash:"
	// followed by the unpadded base64url SHA-256 fingerprint of its signing
	// certificate. iOS apps report "https://" followed by RPID.
	Origins []string
	// RelatedOrigins lists further web origins outside RPID that use RPID
	// through related origin requests (WebAuthn L3 §5.11). The caller must
	// also list them in https://<RPID>/.well-known/webauthn.
	RelatedOrigins []string
	// TopOrigins lists the origins of pages that may embed a ceremony in a
	// cross-origin iframe. A response with crossOrigin set is accepted only
	// if its topOrigin is in this list.
	TopOrigins []string
	// UserVerification defaults to UserVerificationPreferred.
	UserVerification UserVerification
	// ResidentKey defaults to ResidentKeyPreferred.
	ResidentKey ResidentKey
	// Attestation defaults to ConveyanceNone.
	Attestation Conveyance
	// AttestationRoots, if set, requires every new credential to carry an
	// attestation certificate that chains to one of these roots. It
	// requires Attestation to be ConveyanceDirect. If nil, attestation
	// statements are verified but not trusted.
	AttestationRoots *x509.CertPool
	// Algorithms lists the accepted credential algorithms in order of
	// preference. The default is EdDSA, ES256 and RS256.
	Algorithms []Algorithm
	// Timeout bounds how long a Challenge is valid. The default is 5
	// minutes.
	Timeout time.Duration
}

// User is the account a credential is registered for.
type User struct {
	// Subject becomes Principal.Subject after a login with the credential.
	Subject string
	// Handle is the WebAuthn user handle, 1 to 64 bytes. It must be the
	// same for every credential of the user and must not contain personal
	// information. Create it once per user with NewUserHandle and store it.
	Handle []byte
	// Name is a human-readable account identifier, such as an email
	// address or username.
	Name string
	// DisplayName is the user's name for display. It may be empty.
	DisplayName string
}

// NewUserHandle returns a random 32-byte user handle.
func NewUserHandle() ([]byte, error) { return randomBytes(32) }

// Credential is a registered public key credential.
type Credential struct {
	// ID is the credential ID.
	ID []byte
	// Subject and UserHandle identify the user, from User.
	Subject    string
	UserHandle []byte
	// PublicKey is the COSE_Key encoded public key.
	PublicKey []byte
	Algorithm Algorithm
	// SignCount is the last signature counter seen. Authenticators that do
	// not implement a counter, such as synced passkeys, always report 0.
	SignCount uint32
	// Transports are hints from the browser, such as "usb" or "internal".
	Transports []string
	// AAGUID identifies the authenticator model. It is often all zeros.
	AAGUID [16]byte
	// BackupEligible reports whether the credential can be synced, as with
	// passkeys. It never changes for a credential.
	BackupEligible bool
	// BackupState reports whether the credential is currently backed up.
	BackupState bool
	// UserVerified reports whether the user was verified at registration.
	UserVerified bool
	// AttestationFormat and AttestationType describe the attestation.
	AttestationFormat string
	AttestationType   AttestationType
}

// CredentialStore looks up and updates registered credentials.
// Implementations must be safe for concurrent use.
type CredentialStore interface {
	// LookupCredential returns ErrCredentialNotFound if no credential has
	// the given ID.
	LookupCredential(ctx context.Context, id []byte) (Credential, error)
	// UpdateCredential persists SignCount and BackupState after a
	// successful login. FinishLogin has already checked the counter
	// against the value LookupCredential returned. To also catch two
	// concurrent logins with a cloned authenticator, an implementation may
	// update atomically and return ErrSignCount if the stored SignCount is
	// no longer lower than the new one (unless both are 0).
	UpdateCredential(ctx context.Context, c Credential) error
}

// Challenge is the server-side state of one ceremony. It must not be sent
// to the client, and it must be used at most once.
type Challenge struct {
	Ceremony  string    `json:"ceremony"`
	Value     []byte    `json:"challenge"`
	ExpiresAt time.Time `json:"expiresAt"`
	// Subject and UserHandle are set for registration and for logins of a
	// known user. They are empty for discoverable logins.
	Subject    string `json:"subject,omitempty"`
	UserHandle []byte `json:"userHandle,omitempty"`
	// AllowedCredentials limits which credentials a login may use.
	AllowedCredentials [][]byte `json:"allowedCredentials,omitempty"`
	// Conditional is set for registrations started with
	// WithConditionalCreate.
	Conditional bool `json:"conditional,omitzero"`
	// Extensions holds the requested extension inputs, which decide the
	// outputs that Finish accepts.
	Extensions ExtensionInputs `json:"extensions,omitzero"`
}

const (
	ceremonyCreate = "webauthn.create"
	ceremonyGet    = "webauthn.get"
)

// Base64URL is a byte string encoded in JSON as unpadded base64url, the
// encoding of binary members in the WebAuthn JSON types.
type Base64URL []byte

var b64 = base64.RawURLEncoding.Strict()

func (b Base64URL) MarshalJSON() ([]byte, error) { return json.Marshal(b64.EncodeToString(b)) }

func (b *Base64URL) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, err := decodeB64(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// decodeB64 decodes strict unpadded base64url. The decoder silently skips
// '\r' and '\n', so the alphabet is checked first to keep exactly one
// encoding per value.
func decodeB64(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return nil, errors.New("invalid base64url character")
		}
	}
	return b64.DecodeString(s)
}

// CredentialDescriptor is PublicKeyCredentialDescriptorJSON.
type CredentialDescriptor struct {
	Type       string    `json:"type"`
	ID         Base64URL `json:"id"`
	Transports []string  `json:"transports,omitempty"`
}

func descriptors(creds []Credential) []CredentialDescriptor {
	out := make([]CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		out = append(out, CredentialDescriptor{Type: "public-key", ID: c.ID, Transports: c.Transports})
	}
	return out
}

// RelyingParty runs registration and authentication ceremonies.
type RelyingParty struct {
	cfg      Config
	rpIDHash [32]byte
	store    CredentialStore
	now      func() time.Time
}

// Option configures a RelyingParty.
type Option func(*RelyingParty)

// WithClock overrides the clock, for tests.
func WithClock(now func() time.Time) Option { return func(rp *RelyingParty) { rp.now = now } }

// CeremonyOption configures one ceremony started by BeginRegistration,
// BeginLogin or BeginDiscoverableLogin.
type CeremonyOption func(*ceremonyOptions)

type ceremonyOptions struct {
	conditional bool
	extensions  ExtensionInputs
}

// WithConditionalCreate starts a registration with conditional
// mediation, where the browser may create a passkey without prompting the
// user. In the browser, call
// navigator.credentials.create({mediation: "conditional", publicKey}).
// The response may then lack the user presence flag; the
// UserVerification policy still applies. Only BeginRegistration accepts
// it.
func WithConditionalCreate() CeremonyOption {
	return func(o *ceremonyOptions) { o.conditional = true }
}

// WithExtensions requests extensions. Their outputs are returned in
// Registration.Extensions or Login.Extensions.
func WithExtensions(in ExtensionInputs) CeremonyOption {
	return func(o *ceremonyOptions) { o.extensions = in }
}

// maxResponseSize bounds the JSON of a browser response.
const maxResponseSize = 64 << 10

// New returns a RelyingParty for cfg backed by store.
func New(cfg Config, store CredentialStore, opts ...Option) (*RelyingParty, error) {
	if store == nil {
		return nil, errors.New("webauthn: store is required")
	}
	if cfg.RPID == "" || strings.ToLower(cfg.RPID) != cfg.RPID || strings.ContainsAny(cfg.RPID, ":/") {
		return nil, fmt.Errorf("webauthn: RPID %q must be a lowercase domain", cfg.RPID)
	}
	if cfg.RPName == "" {
		cfg.RPName = cfg.RPID
	}
	if len(cfg.Origins) == 0 {
		return nil, errors.New("webauthn: at least one origin is required")
	}
	cfg.Origins = slices.Clone(cfg.Origins)
	for _, o := range cfg.Origins {
		if err := checkOrigin(o, cfg.RPID); err != nil {
			return nil, err
		}
	}
	cfg.RelatedOrigins = slices.Clone(cfg.RelatedOrigins)
	cfg.TopOrigins = slices.Clone(cfg.TopOrigins)
	for _, o := range slices.Concat(cfg.RelatedOrigins, cfg.TopOrigins) {
		if _, err := webOriginHost(o); err != nil {
			return nil, err
		}
	}
	cfg.UserVerification = cmp.Or(cfg.UserVerification, UserVerificationPreferred)
	if !slices.Contains([]UserVerification{UserVerificationRequired, UserVerificationPreferred, UserVerificationDiscouraged}, cfg.UserVerification) {
		return nil, fmt.Errorf("webauthn: unknown user verification %q", cfg.UserVerification)
	}
	cfg.ResidentKey = cmp.Or(cfg.ResidentKey, ResidentKeyPreferred)
	if !slices.Contains([]ResidentKey{ResidentKeyRequired, ResidentKeyPreferred, ResidentKeyDiscouraged}, cfg.ResidentKey) {
		return nil, fmt.Errorf("webauthn: unknown resident key requirement %q", cfg.ResidentKey)
	}
	cfg.Attestation = cmp.Or(cfg.Attestation, ConveyanceNone)
	if !slices.Contains([]Conveyance{ConveyanceNone, ConveyanceIndirect, ConveyanceDirect}, cfg.Attestation) {
		return nil, fmt.Errorf("webauthn: unknown attestation conveyance %q", cfg.Attestation)
	}
	if cfg.AttestationRoots != nil && cfg.Attestation != ConveyanceDirect {
		return nil, errors.New("webauthn: AttestationRoots requires ConveyanceDirect")
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []Algorithm{EdDSA, ES256, RS256}
	}
	cfg.Algorithms = slices.Clone(cfg.Algorithms)
	for _, a := range cfg.Algorithms {
		if !a.supported() {
			return nil, fmt.Errorf("webauthn: unsupported algorithm %v", a)
		}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Minute
	}
	if cfg.Timeout < 0 {
		return nil, errors.New("webauthn: negative timeout")
	}

	rp := &RelyingParty{cfg: cfg, rpIDHash: sha256.Sum256([]byte(cfg.RPID)), store: store, now: time.Now}
	for _, opt := range opts {
		opt(rp)
	}
	return rp, nil
}

const androidOriginPrefix = "android:apk-key-hash:"

func checkOrigin(origin, rpID string) error {
	if hash, ok := strings.CutPrefix(origin, androidOriginPrefix); ok {
		if b, err := decodeB64(hash); err != nil || len(b) != sha256.Size {
			return fmt.Errorf("webauthn: origin %q must end in an unpadded base64url SHA-256 hash", origin)
		}
		return nil
	}
	host, err := webOriginHost(origin)
	if err != nil {
		return err
	}
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return fmt.Errorf("webauthn: origin %q is not within RP ID %q", origin, rpID)
	}
	return nil
}

func webOriginHost(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return "", fmt.Errorf("webauthn: origin %q must be scheme://host[:port]", origin)
	}
	host := u.Hostname()
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && (host == "localhost" || isLoopback(host)):
	default:
		return "", fmt.Errorf("webauthn: origin %q must use https", origin)
	}
	if origin != u.Scheme+"://"+u.Host || strings.ToLower(u.Host) != u.Host {
		return "", fmt.Errorf("webauthn: origin %q is not in serialized form", origin)
	}
	return host, nil
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (rp *RelyingParty) newChallenge(ceremony string, allowed [][]byte, opts []CeremonyOption) (Challenge, ExtensionInputs, error) {
	var o ceremonyOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.conditional && ceremony != ceremonyCreate {
		return Challenge{}, ExtensionInputs{}, errors.New("webauthn: conditional create applies only to registrations")
	}
	if err := o.extensions.check(ceremony, allowed); err != nil {
		return Challenge{}, ExtensionInputs{}, err
	}
	v, err := randomBytes(32)
	if err != nil {
		return Challenge{}, ExtensionInputs{}, err
	}
	return Challenge{
		Ceremony:           ceremony,
		Value:              v,
		ExpiresAt:          rp.now().Add(rp.cfg.Timeout),
		AllowedCredentials: allowed,
		Conditional:        o.conditional,
		Extensions:         o.extensions,
	}, o.extensions, nil
}

// clientData is CollectedClientData (WebAuthn §5.8.1).
type clientData struct {
	Type        string  `json:"type"`
	Challenge   string  `json:"challenge"`
	Origin      string  `json:"origin"`
	CrossOrigin bool    `json:"crossOrigin"`
	TopOrigin   *string `json:"topOrigin"`
}

// verifyClientData checks the client data of a response against the
// ceremony and returns its SHA-256 hash.
func (rp *RelyingParty) verifyClientData(raw []byte, ch Challenge, ceremony string) ([32]byte, error) {
	if ch.Ceremony != ceremony || len(ch.Value) == 0 {
		return [32]byte{}, fmt.Errorf("%w: challenge is not for %s", ErrChallenge, ceremony)
	}
	if !rp.now().Before(ch.ExpiresAt) {
		return [32]byte{}, fmt.Errorf("%w: expired", ErrChallenge)
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return [32]byte{}, fmt.Errorf("%w: client data: %v", ErrMalformed, err)
	}
	if cd.Type != ceremony {
		return [32]byte{}, fmt.Errorf("%w: client data type %q", ErrMalformed, cd.Type)
	}
	got, err := decodeB64(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, ch.Value) != 1 {
		return [32]byte{}, ErrChallenge
	}
	if !slices.Contains(rp.cfg.Origins, cd.Origin) && !slices.Contains(rp.cfg.RelatedOrigins, cd.Origin) {
		return [32]byte{}, fmt.Errorf("%w: %q", ErrOrigin, cd.Origin)
	}
	switch {
	case cd.CrossOrigin && (cd.TopOrigin == nil || !slices.Contains(rp.cfg.TopOrigins, *cd.TopOrigin)):
		return [32]byte{}, fmt.Errorf("%w: cross-origin iframe without an allowed topOrigin", ErrOrigin)
	case !cd.CrossOrigin && cd.TopOrigin != nil:
		return [32]byte{}, fmt.Errorf("%w: topOrigin without crossOrigin", ErrOrigin)
	}
	return sha256.Sum256(raw), nil
}

// verifyAuthData applies the checks shared by both ceremonies.
func (rp *RelyingParty) verifyAuthData(ad *authData, rpIDHash []byte, requirePresence bool) error {
	if !bytes.Equal(ad.rpIDHash, rpIDHash) {
		return ErrRPID
	}
	if requirePresence && !ad.has(flagUP) {
		return ErrUserNotPresent
	}
	if rp.cfg.UserVerification == UserVerificationRequired && !ad.has(flagUV) {
		return ErrUserNotVerified
	}
	return nil
}

// credentialEnvelope holds the members shared by RegistrationResponseJSON
// and AuthenticationResponseJSON.
type credentialEnvelope struct {
	ID                     string                    `json:"id"`
	RawID                  Base64URL                 `json:"rawId"`
	Type                   string                    `json:"type"`
	ClientExtensionResults map[string]jsontext.Value `json:"clientExtensionResults"`
}

func (e credentialEnvelope) check() error {
	if e.Type != "public-key" || len(e.RawID) == 0 || e.ID != b64.EncodeToString(e.RawID) {
		return fmt.Errorf("%w: invalid credential id or type", ErrMalformed)
	}
	return nil
}

func unmarshalResponse(data []byte, v any) error {
	if len(data) > maxResponseSize {
		return fmt.Errorf("%w: response larger than %d bytes", ErrMalformed, maxResponseSize)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return nil
}
