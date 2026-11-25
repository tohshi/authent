// Package totp implements time-based one-time passwords (TOTP, RFC 6238)
// on top of HOTP (RFC 4226), for use as a second authentication factor.
//
// A typical enrollment generates a Key with GenerateKey, shows Key.URI to
// the user as a QR code, and asks for the first code. Key.Verify checks that
// code; on success the key and the returned counter are stored. Later logins
// go through an Authenticator, which rejects codes that were already used.
//
// Secrets must be stored so that they can be read back. Encrypt them at
// rest. Rate limiting is left to the caller: a 6-digit code can be guessed
// with about 500,000 attempts on average, so limit failed attempts per
// subject.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Algorithm is the HMAC hash function of a key.
type Algorithm string

const (
	// SHA1 is the RFC 6238 default and the only algorithm that every
	// authenticator app supports.
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

func (a Algorithm) hash() (func() hash.Hash, int, bool) {
	switch a {
	case SHA1:
		return sha1.New, sha1.Size, true
	case SHA256:
		return sha256.New, sha256.Size, true
	case SHA512:
		return sha512.New, sha512.Size, true
	}
	return nil, 0, false
}

const (
	// MinSecretLength is the shortest secret accepted, in bytes. RFC 4226
	// §4 requires at least 128 bits.
	MinSecretLength = 16
	// DefaultDigits and DefaultPeriod are the parameters every
	// authenticator app supports. Many apps ignore other values in the URI.
	DefaultDigits = 6
	DefaultPeriod = 30 * time.Second
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Key is a TOTP secret and its parameters.
type Key struct {
	// Secret is the shared HMAC key.
	Secret []byte
	// Algorithm is SHA1, SHA256 or SHA512.
	Algorithm Algorithm
	// Digits is the code length, from 6 to 8.
	Digits int
	// Period is the time step. It must be a whole number of seconds.
	Period time.Duration
}

// KeyOption configures GenerateKey.
type KeyOption func(*Key)

// WithAlgorithm sets the hash algorithm. The default is SHA1. The secret
// length follows the hash output size, as RFC 6238 recommends.
func WithAlgorithm(a Algorithm) KeyOption { return func(k *Key) { k.Algorithm = a } }

// WithDigits sets the code length. The default is 6.
func WithDigits(n int) KeyOption { return func(k *Key) { k.Digits = n } }

// WithPeriod sets the time step. The default is 30 seconds.
func WithPeriod(d time.Duration) KeyOption { return func(k *Key) { k.Period = d } }

// GenerateKey returns a key with a random secret as long as the hash output.
func GenerateKey(opts ...KeyOption) (Key, error) {
	k := Key{Algorithm: SHA1, Digits: DefaultDigits, Period: DefaultPeriod}
	for _, opt := range opts {
		opt(&k)
	}
	_, size, ok := k.Algorithm.hash()
	if !ok {
		return Key{}, fmt.Errorf("totp: unsupported algorithm %q", k.Algorithm)
	}
	k.Secret = make([]byte, size)
	if _, err := rand.Read(k.Secret); err != nil {
		return Key{}, err
	}
	if err := k.Validate(); err != nil {
		return Key{}, err
	}
	return k, nil
}

// Validate reports whether the key can be used.
func (k Key) Validate() error {
	if _, _, ok := k.Algorithm.hash(); !ok {
		return fmt.Errorf("totp: unsupported algorithm %q", k.Algorithm)
	}
	if len(k.Secret) < MinSecretLength {
		return fmt.Errorf("totp: secret shorter than %d bytes", MinSecretLength)
	}
	if k.Digits < 6 || k.Digits > 8 {
		return fmt.Errorf("totp: digits must be between 6 and 8, got %d", k.Digits)
	}
	if k.Period < time.Second || k.Period%time.Second != 0 {
		return fmt.Errorf("totp: period must be a positive whole number of seconds, got %v", k.Period)
	}
	return nil
}

// EncodedSecret returns the secret in unpadded base32, for users who type
// it into their app instead of scanning the QR code.
func (k Key) EncodedSecret() string { return b32.EncodeToString(k.Secret) }

// URI returns the otpauth:// URI that authenticator apps read from a QR
// code. issuer names the service and account names the user within it;
// neither may contain a colon. issuer may be empty but should be set.
func (k Key) URI(issuer, account string) (string, error) {
	if err := k.Validate(); err != nil {
		return "", err
	}
	if account == "" {
		return "", errors.New("totp: account is required")
	}
	if strings.Contains(issuer, ":") || strings.Contains(account, ":") {
		return "", errors.New("totp: issuer and account must not contain a colon")
	}
	label := url.PathEscape(account)
	if issuer != "" {
		label = url.PathEscape(issuer) + ":" + label
	}
	q := []string{"secret=" + k.EncodedSecret()}
	if issuer != "" {
		q = append(q, "issuer="+queryEscape(issuer))
	}
	q = append(q,
		"algorithm="+string(k.Algorithm),
		"digits="+strconv.Itoa(k.Digits),
		"period="+strconv.Itoa(int(k.Period/time.Second)),
	)
	return "otpauth://totp/" + label + "?" + strings.Join(q, "&"), nil
}

// queryEscape escapes spaces as %20, because some apps display "+" as is.
func queryEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// Counter returns the time step that contains t.
func (k Key) Counter(t time.Time) (uint64, error) {
	if err := k.Validate(); err != nil {
		return 0, err
	}
	return k.counter(t)
}

func (k Key) counter(t time.Time) (uint64, error) {
	sec := t.Unix()
	if sec < 0 {
		return 0, errors.New("totp: time before the Unix epoch")
	}
	return uint64(sec) / uint64(k.Period/time.Second), nil
}

// Code returns the code for the time step that contains t.
func (k Key) Code(t time.Time) (string, error) {
	c, err := k.Counter(t)
	if err != nil {
		return "", err
	}
	return k.hotp(c), nil
}

// hotp computes the RFC 4226 value for counter. k must be valid.
func (k Key) hotp(counter uint64) string {
	h, _, _ := k.Algorithm.hash()
	mac := hmac.New(h, k.Secret)
	mac.Write(binary.BigEndian.AppendUint64(nil, counter))
	sum := mac.Sum(nil)
	// RFC 4226 §5.3 dynamic truncation.
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range k.Digits {
		mod *= 10
	}
	s := strconv.FormatUint(uint64(v%mod), 10)
	return strings.Repeat("0", k.Digits-len(s)) + s
}

var errMalformedCode = errors.New("malformed code")

// matches returns, in ascending order, the counters within skew steps of t
// whose code equals code. Every candidate is computed and compared in
// constant time.
func (k Key) matches(code string, t time.Time, skew uint) ([]uint64, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	now, err := k.counter(t)
	if err != nil {
		return nil, err
	}
	if len(code) != k.Digits || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return nil, errMalformedCode
	}
	var out []uint64
	lo := now - min(now, uint64(skew))
	for c := lo; c <= now+uint64(skew); c++ {
		if subtle.ConstantTimeCompare([]byte(k.hotp(c)), []byte(code)) == 1 {
			out = append(out, c)
		}
	}
	return out, nil
}

// Verify checks code against the time steps within skew steps of t and
// returns the latest matching counter. It does not prevent reuse of a code;
// use it to confirm enrollment and store the counter as
// Credential.LastCounter, then use an Authenticator for logins. code must
// consist of exactly Digits ASCII digits; strip spaces before calling.
func (k Key) Verify(code string, t time.Time, skew uint) (uint64, error) {
	if skew > MaxSkew {
		return 0, fmt.Errorf("totp: skew larger than %d", MaxSkew)
	}
	m, err := k.matches(code, t, skew)
	switch {
	case errors.Is(err, errMalformedCode):
		return 0, fmt.Errorf("%w: %v", ErrInvalidCode, err)
	case err != nil:
		return 0, err
	case len(m) == 0:
		return 0, ErrInvalidCode
	}
	return slices.Max(m), nil
}
