package password

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// DefaultMinLength is the minimum for a password used as a single factor.
	DefaultMinLength = 15
	// DefaultMaxLength allows long passphrases while bounding input size.
	DefaultMaxLength = 1024
)

var (
	ErrTooShort        = errors.New("password: too short")
	ErrTooLong         = errors.New("password: too long")
	ErrBreached        = errors.New("password: found in breach data")
	ErrBlocked         = errors.New("password: blocked")
	ErrInvalidEncoding = errors.New("password: invalid UTF-8")
)

// BreachChecker reports whether a complete password occurs in breach data.
// Implementations must return an error if the check cannot be completed.
type BreachChecker interface {
	Breached(ctx context.Context, password string) (bool, error)
}

// Blocklist checks complete passwords against common or context-specific
// values. It must not reject a password merely because it contains a listed
// word as a substring.
type Blocklist interface {
	Blocked(ctx context.Context, password string) (bool, error)
}

// Policy validates passwords when they are established or changed. It does
// not apply to login or rehashing, so existing credentials remain usable.
type Policy struct {
	minLength int
	maxLength int
	checker   BreachChecker
	blocklist Blocklist
}

// PolicyOption configures optional policy checks.
type PolicyOption func(*Policy) error

// WithBlocklist adds a complete-password blocklist. A caller may supply a
// custom implementation to use account or service-specific data.
func WithBlocklist(blocklist Blocklist) PolicyOption {
	return func(p *Policy) error {
		if blocklist == nil {
			return errors.New("password: nil blocklist")
		}
		p.blocklist = blocklist
		return nil
	}
}

// NewPolicy creates a policy with character limits and a required breach
// checker. Use DefaultMinLength and DefaultMaxLength for the standard limits.
func NewPolicy(minLength, maxLength int, checker BreachChecker, opts ...PolicyOption) (*Policy, error) {
	if minLength < 1 || maxLength < minLength || checker == nil {
		return nil, errors.New("password: invalid policy configuration")
	}
	p := &Policy{minLength: minLength, maxLength: maxLength, checker: checker}
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("password: nil policy option")
		}
		if err := opt(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Check validates a prospective password. Length is measured in Unicode code
// points after NFC normalization. A lookup failure is returned as an error,
// never treated as a clean result. Use Hash to validate and hash in one call.
func (p *Policy) Check(ctx context.Context, password string) error {
	_, err := p.check(ctx, password)
	return err
}

// Hash validates password and creates an NFC-tagged Argon2id hash. Verification
// of this hash normalizes submitted passwords; existing raw hashes still use
// their original byte sequence.
func (p *Policy) Hash(ctx context.Context, hasher *Hasher, password string) (string, error) {
	normalized, err := p.check(ctx, password)
	if err != nil {
		return "", err
	}
	return hasher.hash(normalized, true)
}

func (p *Policy) check(ctx context.Context, password string) (string, error) {
	if !utf8.ValidString(password) {
		return "", ErrInvalidEncoding
	}
	password = norm.NFC.String(password)
	length := utf8.RuneCountInString(password)
	if length < p.minLength {
		return "", ErrTooShort
	}
	if length > p.maxLength {
		return "", ErrTooLong
	}
	if p.blocklist != nil {
		blocked, err := p.blocklist.Blocked(ctx, password)
		if err != nil {
			return "", fmt.Errorf("password: blocklist check: %w", err)
		}
		if blocked {
			return "", ErrBlocked
		}
	}
	breached, err := p.checker.Breached(ctx, password)
	if err != nil {
		return "", fmt.Errorf("password: breach check: %w", err)
	}
	if breached {
		return "", ErrBreached
	}
	return password, nil
}
