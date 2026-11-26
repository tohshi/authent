package totp

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidURI is returned by ParseURI.
var ErrInvalidURI = errors.New("totp: invalid otpauth URI")

// ProvisioningURI is the content of an otpauth:// URI.
type ProvisioningURI struct {
	Type    URIType
	Key     Key
	Issuer  string
	Account string
	// Counter is the counter of the next HOTP code. It is zero for TOTP,
	// and Key.Period is zero for HOTP.
	Counter uint64
}

// URI formats p as Key.URI or Key.HOTPURI does.
func (p ProvisioningURI) URI() (string, error) {
	if p.Type == TypeHOTP {
		return p.Key.HOTPURI(p.Issuer, p.Account, p.Counter)
	}
	return p.Key.URI(p.Issuer, p.Account)
}

// ParseURI parses an otpauth:// URI in the Key URI format that
// authenticator apps read, as produced by Key.URI and Key.HOTPURI.
//
// It is strict: the scheme and type are lowercase; the label is
// "account" or "issuer:account" with at most one colon; the secret is
// unpadded upper-case base32; parameters may not repeat, be empty or be
// unknown (period is TOTP only, counter is HOTP only and required); numbers
// are plain decimal; an issuer parameter must equal the label's issuer; and
// the resulting Key must be valid. Missing algorithm, digits and period
// take the defaults SHA1, 6 and 30 seconds.
func ParseURI(s string) (ProvisioningURI, error) {
	p, err := parseURI(s)
	if err != nil {
		return ProvisioningURI{}, fmt.Errorf("%w: %v", ErrInvalidURI, err)
	}
	return p, nil
}

func parseURI(s string) (ProvisioningURI, error) {
	rest, ok := strings.CutPrefix(s, "otpauth://")
	if !ok {
		return ProvisioningURI{}, errors.New("scheme is not otpauth")
	}
	if strings.ContainsAny(s, "#") {
		return ProvisioningURI{}, errors.New("fragment")
	}
	typ, rest, _ := strings.Cut(rest, "/")
	p := ProvisioningURI{Type: URIType(typ)}
	if p.Type != TypeTOTP && p.Type != TypeHOTP {
		return ProvisioningURI{}, fmt.Errorf("unknown type %q", typ)
	}
	label, query, ok := strings.Cut(rest, "?")
	if !ok {
		return ProvisioningURI{}, errors.New("no parameters")
	}
	if err := p.parseLabel(label); err != nil {
		return ProvisioningURI{}, err
	}
	params, err := parseParams(query)
	if err != nil {
		return ProvisioningURI{}, err
	}

	p.Key = Key{Algorithm: SHA1, Digits: DefaultDigits}
	if p.Type == TypeTOTP {
		p.Key.Period = DefaultPeriod
	}
	for name, v := range params {
		switch name {
		case "secret":
			p.Key.Secret, err = b32.DecodeString(v)
			if err == nil && b32.EncodeToString(p.Key.Secret) != v {
				err = errors.New("non-canonical base32")
			}
		case "issuer":
			if p.Issuer != "" && p.Issuer != v {
				err = errors.New("issuer parameter differs from the label")
			}
			p.Issuer = v
		case "algorithm":
			p.Key.Algorithm = Algorithm(v)
		case "digits":
			n, perr := parseCanonicalDecimal(v)
			if perr != nil || n > 8 {
				return ProvisioningURI{}, fmt.Errorf("digits: invalid number %q", v)
			}
			p.Key.Digits = int(n)
		case "period":
			if p.Type != TypeTOTP {
				return ProvisioningURI{}, errors.New("period in a HOTP URI")
			}
			n, perr := parseCanonicalDecimal(v)
			if perr != nil || n > math.MaxInt64/uint64(time.Second) {
				return ProvisioningURI{}, fmt.Errorf("period: invalid number %q", v)
			}
			p.Key.Period = time.Duration(n) * time.Second
		case "counter":
			if p.Type != TypeHOTP {
				return ProvisioningURI{}, errors.New("counter in a TOTP URI")
			}
			p.Counter, err = parseCanonicalDecimal(v)
		default:
			return ProvisioningURI{}, fmt.Errorf("unknown parameter %q", name)
		}
		if err != nil {
			return ProvisioningURI{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if _, ok := params["secret"]; !ok {
		return ProvisioningURI{}, errors.New("no secret")
	}
	if _, ok := params["counter"]; p.Type == TypeHOTP && !ok {
		return ProvisioningURI{}, errors.New("no counter")
	}
	if strings.Contains(p.Issuer, ":") {
		return ProvisioningURI{}, errors.New("issuer contains a colon")
	}
	if p.Type == TypeTOTP {
		err = p.Key.Validate()
	} else {
		err = p.Key.validateHOTP()
	}
	if err != nil {
		return ProvisioningURI{}, err
	}
	return p, nil
}

// parseLabel accepts "account" and "issuer:account", with optional spaces
// after the colon as the Key URI format allows.
func (p *ProvisioningURI) parseLabel(label string) error {
	if strings.Contains(label, "/") {
		return errors.New("label contains a slash")
	}
	l, err := url.PathUnescape(label)
	if err != nil {
		return err
	}
	issuer, account, hasIssuer := strings.Cut(l, ":")
	if hasIssuer {
		account = strings.TrimLeft(account, " ")
	} else {
		issuer, account = "", issuer
	}
	switch {
	case hasIssuer && issuer == "":
		return errors.New("empty issuer in label")
	case account == "":
		return errors.New("empty account")
	case account[0] == ' ':
		return errors.New("account starts with a space")
	case strings.Contains(account, ":"):
		return errors.New("label has more than one colon")
	}
	p.Issuer, p.Account = issuer, account
	return nil
}

func parseParams(query string) (map[string]string, error) {
	params := map[string]string{}
	for part := range strings.SplitSeq(query, "&") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("malformed parameter %q", part)
		}
		uv, err := url.QueryUnescape(v)
		if err != nil {
			return nil, err
		}
		if _, dup := params[k]; dup {
			return nil, fmt.Errorf("repeated parameter %q", k)
		}
		params[k] = uv
	}
	return params, nil
}

func parseCanonicalDecimal(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s {
		return 0, fmt.Errorf("invalid number %q", s)
	}
	return n, nil
}
