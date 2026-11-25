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
package password

import (
	"crypto/rand"
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
	// ErrMalformedHash is returned when an encoded hash cannot be parsed or
	// carries parameters outside the accepted bounds.
	ErrMalformedHash = errors.New("password: malformed hash")
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
	params Params
}

// NewHasher returns a Hasher that creates hashes with p.
func NewHasher(p Params) (*Hasher, error) {
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("password: invalid params: %w", err)
	}
	return &Hasher{params: p}, nil
}

// Hash returns the PHC-encoded Argon2id hash of password with a fresh salt.
func (h *Hasher) Hash(password string) (string, error) {
	return h.hash(password, false)
}

// hash creates either a legacy raw hash or an NFC-tagged hash. NFC-tagged
// hashes are created by Policy.Hash and normalized again during verification.
func (h *Hasher) hash(password string, normalize bool) (string, error) {
	if normalize {
		password = norm.NFC.String(password)
	}
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generating salt: %w", err)
	}
	key := derive(password, salt, h.params)
	return encode(h.params, salt, key, normalize), nil
}

// Verify reports whether password matches encoded. It returns nil on a
// match, ErrMismatch on a mismatch and ErrMalformedHash if encoded is not a
// valid Argon2id hash. The comparison is constant time.
//
// The parameters stored in encoded are used, so hashes created with older
// parameters still verify; use NeedsRehash to upgrade them.
func (h *Hasher) Verify(password, encoded string) error {
	p, salt, want, normalize, err := decode(encoded)
	if err != nil {
		return err
	}
	valid := true
	if normalize {
		valid = utf8.ValidString(password)
		if valid {
			password = norm.NFC.String(password)
		}
	}
	got := derive(password, salt, p)
	if subtle.ConstantTimeCompare(got, want) != 1 || !valid {
		return ErrMismatch
	}
	return nil
}

// NeedsRehash reports whether encoded was created with parameters other than
// the Hasher's, in which case the password should be hashed again after a
// successful Verify.
func (h *Hasher) NeedsRehash(encoded string) (bool, error) {
	p, salt, key, _, err := decode(encoded)
	if err != nil {
		return false, err
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	return p != h.params, nil
}

func derive(password string, salt []byte, p Params) []byte {
	return argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
}

var b64 = base64.RawStdEncoding.Strict()

func encode(p Params, salt, key []byte, normalize bool) string {
	costs := fmt.Sprintf("m=%d,t=%d,p=%d", p.Memory, p.Iterations, p.Parallelism)
	if normalize {
		costs += ",norm=nfc"
	}
	return fmt.Sprintf("$argon2id$v=%d$%s$%s$%s",
		argon2.Version, costs, b64.EncodeToString(salt), b64.EncodeToString(key))
}

func decode(encoded string) (Params, []byte, []byte, bool, error) {
	var p Params
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, false, ErrMalformedHash
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return p, nil, nil, false, ErrMalformedHash
	}

	costs := strings.Split(parts[3], ",")
	if len(costs) != 3 && (len(costs) != 4 || costs[3] != "norm=nfc") {
		return p, nil, nil, false, ErrMalformedHash
	}
	normalize := len(costs) == 4
	m, err1 := parseCost(costs[0], "m=", 32)
	t, err2 := parseCost(costs[1], "t=", 32)
	l, err3 := parseCost(costs[2], "p=", 8)
	if err := errors.Join(err1, err2, err3); err != nil {
		return p, nil, nil, false, ErrMalformedHash
	}

	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, false, ErrMalformedHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, false, ErrMalformedHash
	}

	p = Params{
		Memory:      uint32(m),
		Iterations:  uint32(t),
		Parallelism: uint8(l),
		SaltLength:  uint32(len(salt)),
		KeyLength:   uint32(len(key)),
	}
	if p.validate() != nil {
		return p, nil, nil, false, ErrMalformedHash
	}
	return p, salt, key, normalize, nil
}

func parseCost(s, prefix string, bits int) (uint64, error) {
	v, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return 0, ErrMalformedHash
	}
	return strconv.ParseUint(v, 10, bits)
}
