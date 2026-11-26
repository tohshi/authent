package password

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// Bounds applied to legacy hashes. Each is well above the current default
// of the library that creates the format.
const (
	maxBcryptCost        = 16
	maxScryptMemoryBytes = 256 << 20
	maxScryptWork        = 1 << 24
	maxPBKDF2Iterations  = 10_000_000
)

// legacy hashes are verified against the raw password bytes, as the systems
// that created them did, and are always upgraded after a successful login.
type legacy struct{}

func (legacy) current(*Hasher) bool { return false }

func (legacy) normalized() bool { return false }

func parseLegacy(encoded string) (storedHash, error) {
	switch {
	case strings.HasPrefix(encoded, "$2"):
		return parseBcrypt(encoded)
	case strings.HasPrefix(encoded, "scrypt:"):
		return parseWerkzeugScrypt(encoded)
	case strings.HasPrefix(encoded, "pbkdf2_sha256$"):
		return parseDjangoPBKDF2(encoded)
	}
	return nil, ErrMalformedHash
}

// Only the first 72 bytes of a password are significant, as in every bcrypt
// implementation.
type bcryptHash struct {
	legacy
	encoded []byte
}

func parseBcrypt(encoded string) (*bcryptHash, error) {
	// $2b$10$ followed by a 22-character salt and a 31-character hash.
	if len(encoded) != 60 || encoded[3] != '$' || encoded[6] != '$' {
		return nil, ErrMalformedHash
	}
	switch encoded[:3] {
	case "$2a", "$2b", "$2y":
	default:
		return nil, ErrMalformedHash
	}
	if !isDigit(encoded[4]) || !isDigit(encoded[5]) {
		return nil, ErrMalformedHash
	}
	cost := int(encoded[4]-'0')*10 + int(encoded[5]-'0')
	if cost < bcrypt.MinCost || cost > maxBcryptCost {
		return nil, ErrMalformedHash
	}
	for i := 7; i < len(encoded); i++ {
		if c := encoded[i]; !isAlnum(c) && c != '.' && c != '/' {
			return nil, ErrMalformedHash
		}
	}
	return &bcryptHash{encoded: []byte(encoded)}, nil
}

func (b *bcryptHash) matches(password string) bool {
	return bcrypt.CompareHashAndPassword(b.encoded, []byte(password)) == nil
}

type werkzeugScryptHash struct {
	legacy
	n, r, p   int
	salt, key []byte
}

func parseWerkzeugScrypt(encoded string) (*werkzeugScryptHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || !validSalt(parts[1]) {
		return nil, ErrMalformedHash
	}
	args := strings.Split(parts[0], ":")
	if len(args) != 4 || args[0] != "scrypt" {
		return nil, ErrMalformedHash
	}
	n, ok1 := parseCanonicalDecimal(args[1], maxScryptWork)
	r, ok2 := parseCanonicalDecimal(args[2], maxScryptWork)
	p, ok3 := parseCanonicalDecimal(args[3], maxScryptWork)
	if !ok1 || !ok2 || !ok3 || n < 2 || n&(n-1) != 0 || r == 0 || p == 0 ||
		scryptMemory(n, r, p) > maxScryptMemoryBytes || n*r > maxScryptWork || n*r*p > maxScryptWork {
		return nil, ErrMalformedHash
	}
	key, err := hex.DecodeString(parts[2])
	if err != nil || hex.EncodeToString(key) != parts[2] || len(key) < minKeyLength || len(key) > maxLength {
		return nil, ErrMalformedHash
	}
	return &werkzeugScryptHash{n: n, r: r, p: p, salt: []byte(parts[1]), key: key}, nil
}

// scryptMemory is the memory scrypt allocates: V (128·r·N bytes), B
// (128·r·p bytes) and XY (256·r bytes).
func scryptMemory(n, r, p int) int { return 128*r*(n+p) + 256*r }

func (s *werkzeugScryptHash) matches(password string) bool {
	got, err := scrypt.Key([]byte(password), s.salt, s.n, s.r, s.p, len(s.key))
	return err == nil && subtle.ConstantTimeCompare(got, s.key) == 1
}

type djangoPBKDF2Hash struct {
	legacy
	iterations int
	salt, key  []byte
}

func parseDjangoPBKDF2(encoded string) (*djangoPBKDF2Hash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" || !validSalt(parts[2]) {
		return nil, ErrMalformedHash
	}
	iterations, ok := parseCanonicalDecimal(parts[1], maxPBKDF2Iterations)
	if !ok || iterations == 0 {
		return nil, ErrMalformedHash
	}
	key, ok := decodeCanonical(base64.StdEncoding.Strict(), parts[3])
	if !ok || len(key) != sha256.Size {
		return nil, ErrMalformedHash
	}
	return &djangoPBKDF2Hash{iterations: iterations, salt: []byte(parts[2]), key: key}, nil
}

func (p *djangoPBKDF2Hash) matches(password string) bool {
	got, err := pbkdf2.Key(sha256.New, password, p.salt, p.iterations, len(p.key))
	return err == nil && subtle.ConstantTimeCompare(got, p.key) == 1
}

// validSalt accepts the alphanumeric salts that Werkzeug and Django generate.
func validSalt(s string) bool {
	if len(s) == 0 || len(s) > maxLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) {
			return false
		}
	}
	return true
}

func parseCanonicalDecimal(s string, max int) (int, bool) {
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 || v > max || strconv.Itoa(v) != s {
		return 0, false
	}
	return v, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
