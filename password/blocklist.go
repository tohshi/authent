package password

import (
	"context"
	"fmt"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// StaticBlocklist matches whole passwords against a fixed set of values. It
// is safe for concurrent use after construction.
type StaticBlocklist struct {
	passwords map[string]struct{}
}

// NewStaticBlocklist creates an exact-match blocklist. Entries are normalized
// to NFC, just like candidates checked by Policy. Include expected passwords
// and their variants explicitly; substrings are never rejected.
func NewStaticBlocklist(passwords ...string) (*StaticBlocklist, error) {
	b := &StaticBlocklist{passwords: make(map[string]struct{}, len(passwords))}
	for i, password := range passwords {
		if !utf8.ValidString(password) {
			return nil, fmt.Errorf("password: blocklist entry %d has invalid UTF-8", i)
		}
		b.passwords[norm.NFC.String(password)] = struct{}{}
	}
	return b, nil
}

// Blocked reports whether the entire password is listed.
func (b *StaticBlocklist) Blocked(_ context.Context, password string) (bool, error) {
	_, found := b.passwords[norm.NFC.String(password)]
	return found, nil
}
