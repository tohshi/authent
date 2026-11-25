package jwt

import (
	"encoding/json/v2"
	"errors"
	"math"
	"strconv"
	"time"
)

// Claims is a JWT claims set (RFC 7519 §4).
//
// Claims are decoded with encoding/json/v2: member names are matched
// case-sensitively, duplicate members are rejected and registered claims
// must have the types defined by RFC 7519.
type Claims struct {
	Issuer    string      `json:"iss,omitempty"`
	Subject   string      `json:"sub,omitempty"`
	Audience  Audience    `json:"aud,omitzero"`
	ExpiresAt NumericDate `json:"exp,omitzero"`
	NotBefore NumericDate `json:"nbf,omitzero"`
	IssuedAt  NumericDate `json:"iat,omitzero"`
	ID        string      `json:"jti,omitempty"`

	// Extra holds all other claims. Numbers decode as float64. When
	// signing, a key that collides with a registered claim is an error.
	Extra map[string]any `json:",embed"`
}

// AsMap returns all claims, registered and extra, as a single map with JSON
// types (numbers are float64, dates are Unix seconds).
func (c Claims) AsMap() (map[string]any, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

// NumericDate is a JSON number of seconds since the Unix epoch.
type NumericDate struct {
	time.Time
}

// NewNumericDate truncates t to whole seconds.
func NewNumericDate(t time.Time) NumericDate {
	return NumericDate{t.Truncate(time.Second)}
}

// Latest date accepted, 9999-12-31T23:59:59Z.
const maxUnixSeconds = 253402300799

func (d NumericDate) MarshalJSON() ([]byte, error) {
	return strconv.AppendInt(nil, d.Unix(), 10), nil
}

func (d *NumericDate) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return errors.New("NumericDate must be a JSON number")
	}
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil || math.IsNaN(f) || f < 0 || f > maxUnixSeconds {
		return errors.New("NumericDate out of range")
	}
	sec, frac := math.Modf(f)
	d.Time = time.Unix(int64(sec), int64(frac*1e9)).UTC()
	return nil
}

// Audience is the "aud" claim. It decodes from a string or an array of
// strings and encodes a single value as a string.
type Audience []string

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *Audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = Audience{s}
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = list
	return nil
}
