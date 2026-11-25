// Package dpop implements OAuth 2.0 Demonstrating Proof of Possession
// (DPoP, RFC 9449).
//
// DPoP binds access and refresh tokens to a key pair held by the client.
// Every request carries a short-lived proof, a JWT signed with the private
// key that names the HTTP method and URI of the request, so a stolen token
// is useless without the key.
//
// Clients use a [Prover], usually through a [Transport] that adds proofs
// to outgoing requests and handles server-provided nonces. The oidc package
// uses both when its Config.DPoP is set.
//
// Resource servers use an [Authenticator] to accept DPoP-bound JWT access
// tokens, or a [Verifier] to check proofs on their own. The package does
// not depend on an HTTP framework: the caller passes the method, the
// absolute request URI and the header values in a [Request].
package dpop

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

// Header and token type names.
const (
	// HeaderName is the request header that carries the proof.
	HeaderName = "DPoP"
	// NonceHeaderName is the response header that carries a server nonce.
	NonceHeaderName = "DPoP-Nonce"
	// TokenType is the token_type of DPoP-bound access tokens and the
	// Authorization scheme used to send them.
	TokenType = "DPoP"

	proofType = "dpop+jwt"
)

var (
	// ErrInvalidProof means the DPoP proof is missing, malformed or does
	// not match the request (error code "invalid_dpop_proof"). It wraps
	// authent.ErrUnauthenticated.
	ErrInvalidProof = fmt.Errorf("dpop: invalid proof: %w", authent.ErrUnauthenticated)
	// ErrReplayed means the proof was already used. It wraps
	// ErrInvalidProof.
	ErrReplayed = fmt.Errorf("%w: replayed", ErrInvalidProof)
	// ErrUseNonce means the proof lacks a valid server-provided nonce
	// (error code "use_dpop_nonce"). Respond with a fresh nonce in the
	// DPoP-Nonce header. It wraps authent.ErrUnauthenticated.
	ErrUseNonce = fmt.Errorf("dpop: fresh nonce required: %w", authent.ErrUnauthenticated)
	// ErrKeyBinding means the access token is not bound to the key that
	// signed the proof, or is not DPoP-bound at all (error code
	// "invalid_token"). It wraps authent.ErrUnauthenticated.
	ErrKeyBinding = fmt.Errorf("dpop: access token not bound to the proof key: %w", authent.ErrUnauthenticated)
	// ErrNoToken means the request has no DPoP access token. It wraps
	// authent.ErrUnauthenticated.
	ErrNoToken = fmt.Errorf("dpop: no DPoP access token: %w", authent.ErrUnauthenticated)
)

// proofClaims are the claims of a DPoP proof (RFC 9449 §4.2).
type proofClaims struct {
	JTI   string          `json:"jti"`
	HTM   string          `json:"htm"`
	HTU   string          `json:"htu"`
	IAT   jwt.NumericDate `json:"iat,omitzero"`
	Nonce string          `json:"nonce,omitempty"`
	ATH   string          `json:"ath,omitempty"`
}

// Thumbprint returns the JWK SHA-256 thumbprint of key, base64url-encoded:
// the value of the "jkt" confirmation member (RFC 9449 §6.1) and of the
// "dpop_jkt" authorization request parameter (§10).
func Thumbprint(key jwt.JWK) (string, error) {
	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// AccessTokenHash returns the "ath" claim for accessToken: the base64url
// encoding of its SHA-256 hash.
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AccessToken extracts the token from an Authorization header value that
// uses the DPoP scheme (RFC 9449 §7.1). Other schemes, including Bearer,
// return ErrNoToken.
func AccessToken(authorization string) (string, error) {
	scheme, token, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, TokenType) {
		return "", ErrNoToken
	}
	token = strings.TrimLeft(token, " ")
	if !isToken68(token) {
		return "", fmt.Errorf("%w: malformed credentials", ErrNoToken)
	}
	return token, nil
}

// isToken68 reports whether s matches the token68 rule of RFC 9110 §11.2.
func isToken68(s string) bool {
	s = strings.TrimRight(s, "=")
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/') {
			return false
		}
	}
	return true
}

// isNonce reports whether s matches the nonce rule of RFC 9449 §8.1
// (1*NQCHAR).
func isNonce(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

var errBadURI = errors.New("dpop: URI must be an absolute http or https URI without user info")

// targetURI parses an absolute http(s) URI and returns it without query
// and fragment, as the "htu" claim requires.
func targetURI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Opaque != "" {
		return nil, errBadURI
	}
	u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""
	return u, nil
}

// normalizeURI applies the syntax-based and scheme-based normalization of
// RFC 3986 §6.2.2 and §6.2.3, which RFC 9449 §4.3 recommends before
// comparing "htu" with the request URI. Query and fragment are dropped.
func normalizeURI(raw string) (string, error) {
	u, err := targetURI(raw)
	if err != nil {
		return "", err
	}
	return origin(u) + removeDotSegments(normalizePercent(u.EscapedPath())), nil
}

// origin returns the normalized scheme and authority of u.
func origin(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 literal
	}
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host
}

// normalizePercent upper-cases percent-encodings and decodes those of
// unreserved characters (RFC 3986 §6.2.2.1 and §6.2.2.2).
func normalizePercent(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] != '%' || i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
			b.WriteByte(p[i])
			continue
		}
		c := unhex(p[i+1])<<4 | unhex(p[i+2])
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteString(strings.ToUpper(p[i+1 : i+3]))
		}
		i += 2
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// removeDotSegments implements RFC 3986 §5.2.4 for an absolute path. An
// empty path becomes "/" (RFC 3986 §6.2.3).
func removeDotSegments(p string) string {
	if p == "" {
		return "/"
	}
	in := strings.Split(strings.TrimPrefix(p, "/"), "/")
	out := make([]string, 0, len(in))
	for i, seg := range in {
		last := i == len(in)-1
		switch seg {
		case ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
			continue
		}
		if last {
			out = append(out, "")
		}
	}
	return "/" + strings.Join(out, "/")
}
