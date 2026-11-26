// Package password hashes and verifies passwords with Argon2id, validates
// new passwords against a policy, and authenticates users against a pluggable
// credential store.
//
// Hashes are encoded in the PHC string format used by the Argon2 reference
// implementation:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
//
// Policy.Hash adds a norm=nfc parameter to mark hashes that use Unicode NFC
// normalization; hashes without it retain their original byte semantics.
// A Hasher with a pepper adds keyid=<id>, before any norm parameter:
//
//	$argon2id$v=19$m=65536,t=3,p=4,keyid=k1,norm=nfc$<salt>$<hash>
//
// The password is normalized first, then keyed with HMAC-SHA-256 under the
// pepper, and the HMAC output is hashed with Argon2id.
//
// Verify also accepts bcrypt, Werkzeug scrypt and Django PBKDF2 hashes so
// that users can be migrated from other systems. These are never created;
// NeedsRehash always reports them as outdated.
package password

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

var (
	// ErrMismatch is returned when a password does not match a hash.
	ErrMismatch = errors.New("password: mismatch")
	// ErrMalformedHash is returned when an encoded hash is not in a supported
	// format or carries parameters outside the accepted bounds.
	ErrMalformedHash = errors.New("password: malformed hash")
	// ErrUnknownPepper is returned when a hash names a pepper key ID that the
	// Hasher was not configured with. It is a configuration error and does
	// not wrap authent.ErrUnauthenticated.
	ErrUnknownPepper = errors.New("password: unknown pepper key ID")
)

// Params are the Argon2id cost parameters.
type Params struct {
	// Memory is the memory cost in KiB.
	Memory uint32
	// Iterations is the time cost.
	Iterations uint32
	// Parallelism is the number of lanes.
	Parallelism uint8
	// SaltLength is the salt size in bytes.
	SaltLength uint32
	// KeyLength is the derived key size in bytes.
	KeyLength uint32
}

// DefaultParams is the second recommended option of RFC 9106 §4
// (64 MiB, 3 passes, 4 lanes).
var DefaultParams = Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// Bounds applied to parameters read from stored hashes, so that a tampered
// hash cannot make verification allocate unbounded memory or CPU.
const (
	maxMemory     = 4 * 1024 * 1024 // 4 GiB in KiB
	maxIterations = 1 << 10
	maxLength     = 1024
	minSaltLength = 8
	minKeyLength  = 16
)

func (p Params) validate() error {
	switch {
	case p.Parallelism == 0:
		return errors.New("parallelism must be at least 1")
	case p.Memory < 8*uint32(p.Parallelism):
		return errors.New("memory must be at least 8 KiB per lane")
	case p.Memory > maxMemory:
		return errors.New("memory is too large")
	case p.Iterations == 0 || p.Iterations > maxIterations:
		return errors.New("iterations out of range")
	case p.SaltLength < minSaltLength || p.SaltLength > maxLength:
		return errors.New("salt length out of range")
	case p.KeyLength < minKeyLength || p.KeyLength > maxLength:
		return errors.New("key length out of range")
	}
	return nil
}

// Hasher hashes and verifies passwords. It is safe for concurrent use.
type Hasher struct {
	params   Params
	pepperID string
	peppers  map[string][]byte
}

// HasherOption configures a Hasher.
type HasherOption func(*Hasher) error

const (
	minPepperLength = 32
	maxPepperIDLen  = 16
)

// WithPepper sets the pepper, a server-side secret of at least 32 bytes
// that new hashes are keyed with. The id is recorded in each hash so that
// the pepper can be rotated; it is 1 to 16 ASCII letters or digits.
func WithPepper(id string, key []byte) HasherOption {
	return func(h *Hasher) error {
		if h.pepperID != "" {
			return errors.New("password: more than one current pepper")
		}
		if err := h.addPepper(id, key); err != nil {
			return err
		}
		h.pepperID = id
		return nil
	}
}

// WithRetiredPepper adds a pepper that is only used to verify existing
// hashes. Hashes keyed with it report NeedsRehash.
func WithRetiredPepper(id string, key []byte) HasherOption {
	return func(h *Hasher) error { return h.addPepper(id, key) }
}

func (h *Hasher) addPepper(id string, key []byte) error {
	if !validPepperID(id) {
		return fmt.Errorf("password: invalid pepper key ID %q", id)
	}
	if len(key) < minPepperLength {
		return fmt.Errorf("password: pepper %q is shorter than %d bytes", id, minPepperLength)
	}
	if _, dup := h.peppers[id]; dup {
		return fmt.Errorf("password: duplicate pepper key ID %q", id)
	}
	h.peppers[id] = bytes.Clone(key)
	return nil
}

func validPepperID(id string) bool {
	if len(id) == 0 || len(id) > maxPepperIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !isAlnum(id[i]) {
			return false
		}
	}
	return true
}

// NewHasher returns a Hasher that creates hashes with p.
func NewHasher(p Params, opts ...HasherOption) (*Hasher, error) {
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("password: invalid params: %w", err)
	}
	h := &Hasher{params: p, peppers: map[string][]byte{}}
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("password: nil hasher option")
		}
		if err := opt(h); err != nil {
			return nil, err
		}
	}
	return h, nil
}

// Hash returns the PHC-encoded Argon2id hash of password with a fresh salt.
func (h *Hasher) Hash(password string) (string, error) {
	return h.hash(password, false)
}

// hash creates either a raw hash or an NFC-tagged hash. NFC-tagged
// hashes are created by Policy.Hash and normalized again during verification.
func (h *Hasher) hash(password string, normalize bool) (string, error) {
	a := &argon2idHash{
		params:    h.params,
		salt:      make([]byte, h.params.SaltLength),
		keyID:     h.pepperID,
		pepper:    h.peppers[h.pepperID],
		normalize: normalize,
	}
	if _, err := rand.Read(a.salt); err != nil {
		return "", fmt.Errorf("password: generating salt: %w", err)
	}
	a.key = a.derive(password)
	return a.encode(), nil
}

// Verify reports whether password matches encoded. It returns nil on a
// match, ErrMismatch on a mismatch, ErrMalformedHash if encoded is not a
// valid hash in a supported format and ErrUnknownPepper if it names a pepper
// the Hasher does not have. The comparison is constant time.
//
// The parameters stored in encoded are used, so hashes created with older
// parameters, a retired pepper or a legacy algorithm still verify; use
// NeedsRehash to upgrade them.
func (h *Hasher) Verify(password, encoded string) error {
	_, err := h.verify(password, encoded)
	return err
}

func (h *Hasher) verify(password, encoded string) (storedHash, error) {
	s, err := h.parse(encoded)
	if err != nil {
		return nil, err
	}
	if !s.matches(password) {
		return nil, ErrMismatch
	}
	return s, nil
}

// NeedsRehash reports whether encoded was created with parameters or a
// pepper other than the Hasher's, or with a legacy algorithm, in which case
// the password should be hashed again after a successful Verify.
func (h *Hasher) NeedsRehash(encoded string) (bool, error) {
	s, err := h.parse(encoded)
	if err != nil {
		return false, err
	}
	return !s.current(h), nil
}

type storedHash interface {
	matches(password string) bool
	current(h *Hasher) bool
	normalized() bool
}

func (h *Hasher) parse(encoded string) (storedHash, error) {
	if !strings.HasPrefix(encoded, "$argon2id$") {
		return parseLegacy(encoded)
	}
	a, err := parseArgon2id(encoded)
	if err != nil {
		return nil, err
	}
	if a.keyID != "" {
		if a.pepper = h.peppers[a.keyID]; a.pepper == nil {
			return nil, fmt.Errorf("%w %q", ErrUnknownPepper, a.keyID)
		}
	}
	return a, nil
}

type argon2idHash struct {
	params    Params
	salt, key []byte
	keyID     string
	pepper    []byte
	normalize bool
}

func (a *argon2idHash) matches(password string) bool {
	valid := !a.normalize || utf8.ValidString(password)
	return subtle.ConstantTimeCompare(a.derive(password), a.key) == 1 && valid
}

func (a *argon2idHash) current(h *Hasher) bool {
	return a.params == h.params && a.keyID == h.pepperID
}

func (a *argon2idHash) normalized() bool { return a.normalize }

func (a *argon2idHash) derive(password string) []byte {
	if a.normalize {
		password = norm.NFC.String(password)
	}
	input := []byte(password)
	if a.pepper != nil {
		mac := hmac.New(sha256.New, a.pepper)
		mac.Write(input)
		input = mac.Sum(nil)
	}
	p := a.params
	return argon2.IDKey(input, a.salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
}

var b64 = base64.RawStdEncoding.Strict()

// decodeCanonical decodes s and rejects any input that is not exactly the
// encoding of its result. Strict decoding alone still skips '\r' and '\n'.
func decodeCanonical(enc *base64.Encoding, s string) ([]byte, bool) {
	b, err := enc.DecodeString(s)
	if err != nil || enc.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

func (a *argon2idHash) encode() string {
	p := a.params
	costs := fmt.Sprintf("m=%d,t=%d,p=%d", p.Memory, p.Iterations, p.Parallelism)
	if a.keyID != "" {
		costs += ",keyid=" + a.keyID
	}
	if a.normalize {
		costs += ",norm=nfc"
	}
	return fmt.Sprintf("$argon2id$v=%d$%s$%s$%s",
		argon2.Version, costs, b64.EncodeToString(a.salt), b64.EncodeToString(a.key))
}

func parseArgon2id(encoded string) (*argon2idHash, error) {
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, ErrMalformedHash
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return nil, ErrMalformedHash
	}

	costs := strings.Split(parts[3], ",")
	if len(costs) < 3 {
		return nil, ErrMalformedHash
	}
	extra := costs[3:]
	var keyID string
	if len(extra) > 0 && strings.HasPrefix(extra[0], "keyid=") {
		keyID = strings.TrimPrefix(extra[0], "keyid=")
		if !validPepperID(keyID) {
			return nil, ErrMalformedHash
		}
		extra = extra[1:]
	}
	normalize := len(extra) > 0 && extra[0] == "norm=nfc"
	if normalize {
		extra = extra[1:]
	}
	if len(extra) != 0 {
		return nil, ErrMalformedHash
	}
	m, err1 := parseCost(costs[0], "m=", 32)
	t, err2 := parseCost(costs[1], "t=", 32)
	l, err3 := parseCost(costs[2], "p=", 8)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, ErrMalformedHash
	}

	salt, ok := decodeCanonical(b64, parts[4])
	if !ok {
		return nil, ErrMalformedHash
	}
	key, ok := decodeCanonical(b64, parts[5])
	if !ok {
		return nil, ErrMalformedHash
	}

	p := Params{
		Memory:      uint32(m),
		Iterations:  uint32(t),
		Parallelism: uint8(l),
		SaltLength:  uint32(len(salt)),
		KeyLength:   uint32(len(key)),
	}
	if p.validate() != nil {
		return nil, ErrMalformedHash
	}
	return &argon2idHash{params: p, salt: salt, key: key, keyID: keyID, normalize: normalize}, nil
}

func parseCost(s, prefix string, bits int) (uint64, error) {
	v, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return 0, ErrMalformedHash
	}
	return strconv.ParseUint(v, 10, bits)
}
