package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Authenticator data flags (WebAuthn §6.1).
const (
	flagUP = 1 << 0 // user present
	flagUV = 1 << 2 // user verified
	flagBE = 1 << 3 // backup eligible
	flagBS = 1 << 4 // backup state
	flagAT = 1 << 6 // attested credential data included
	flagED = 1 << 7 // extension data included
)

// maxCredentialIDLength is the WebAuthn Level 3 limit on credential IDs.
const maxCredentialIDLength = 1023

// authData is parsed authenticator data.
type authData struct {
	raw       []byte
	rpIDHash  []byte
	flags     byte
	signCount uint32

	// Set only when flagAT is set.
	aaguid       [16]byte
	credentialID []byte
	publicKey    []byte // COSE_Key, exactly as encoded by the authenticator

	extensions cborMap // set only when flagED is set
}

func (a *authData) has(flag byte) bool { return a.flags&flag != 0 }

var errAuthData = errors.New("invalid authenticator data")

// parseAuthData parses authenticator data. Every byte must be accounted
// for: trailing data after the declared parts is rejected.
func parseAuthData(raw []byte) (*authData, error) {
	if len(raw) < 37 {
		return nil, fmt.Errorf("%w: too short", errAuthData)
	}
	a := &authData{
		raw:       raw,
		rpIDHash:  raw[:32],
		flags:     raw[32],
		signCount: binary.BigEndian.Uint32(raw[33:37]),
	}
	rest := raw[37:]

	if a.has(flagAT) {
		if len(rest) < 18 {
			return nil, fmt.Errorf("%w: truncated attested credential data", errAuthData)
		}
		copy(a.aaguid[:], rest[:16])
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n == 0 || n > maxCredentialIDLength || n > len(rest) {
			return nil, fmt.Errorf("%w: credential ID length %d", errAuthData, n)
		}
		a.credentialID = rest[:n]
		rest = rest[n:]
		// The COSE key is not length-prefixed; decoding it tells where it
		// ends.
		v, after, err := cborDecode(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: credential public key: %v", errAuthData, err)
		}
		if _, ok := v.(cborMap); !ok {
			return nil, fmt.Errorf("%w: credential public key is not a map", errAuthData)
		}
		a.publicKey = rest[:len(rest)-len(after)]
		rest = after
	}

	if a.has(flagED) {
		v, after, err := cborDecode(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: extensions: %v", errAuthData, err)
		}
		m, ok := v.(cborMap)
		if !ok {
			return nil, fmt.Errorf("%w: extensions are not a map", errAuthData)
		}
		a.extensions = m
		rest = after
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", errAuthData, len(rest))
	}
	// A credential that is not backup eligible cannot be backed up (§6.1.3).
	if a.has(flagBS) && !a.has(flagBE) {
		return nil, fmt.Errorf("%w: backup state set without backup eligibility", errAuthData)
	}
	return a, nil
}
