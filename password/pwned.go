package password

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	pwnedRangeURL = "https://api.pwnedpasswords.com/range/"
	maxPwnedReply = 1 << 20
)

// PwnedPasswordsChecker checks the Have I Been Pwned password range API.
// Only the first five hex digits of the password's SHA-1 digest leave the
// process. SHA-1 is used for this lookup only, never for password storage.
type PwnedPasswordsChecker struct {
	client *http.Client
}

// NewPwnedPasswordsChecker creates a checker. If client is nil, requests
// use a five-second timeout. A custom client can supply a proxy or timeout.
func NewPwnedPasswordsChecker(client *http.Client) *PwnedPasswordsChecker {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &PwnedPasswordsChecker{client: client}
}

// Breached reports whether password occurs in the Pwned Passwords corpus.
// A failed or malformed API response returns an error.
func (c *PwnedPasswordsChecker) Breached(ctx context.Context, password string) (bool, error) {
	digest := sha1.Sum([]byte(password))
	hash := make([]byte, hex.EncodedLen(len(digest)))
	hex.Encode(hash, digest[:])
	for i := range hash {
		if hash[i] >= 'a' && hash[i] <= 'f' {
			hash[i] -= 'a' - 'A'
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pwnedRangeURL+string(hash[:5]), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("password: querying Pwned Passwords: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("password: Pwned Passwords returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPwnedReply+1))
	if err != nil {
		return false, fmt.Errorf("password: reading Pwned Passwords response: %w", err)
	}
	if len(data) == 0 || len(data) > maxPwnedReply {
		return false, fmt.Errorf("password: invalid Pwned Passwords response size")
	}

	var found bool
	for line := range bytes.SplitSeq(data, []byte{'\n'}) {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			continue // The response may end with a newline.
		}
		if len(line) < 37 || line[35] != ':' {
			return false, fmt.Errorf("password: malformed Pwned Passwords response")
		}
		for _, digit := range line[:35] {
			if !((digit >= '0' && digit <= '9') || (digit >= 'A' && digit <= 'F')) {
				return false, fmt.Errorf("password: malformed Pwned Passwords response")
			}
		}
		count, err := strconv.ParseUint(string(line[36:]), 10, 64)
		if err != nil {
			return false, fmt.Errorf("password: malformed Pwned Passwords response: %w", err)
		}
		if bytes.Equal(line[:35], hash[5:]) && count > 0 {
			found = true
		}
	}
	return found, nil
}
