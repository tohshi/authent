package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/v2"
	"slices"
	"sync"
	"testing"
	"time"
)

// cborEnc encodes the values used by the test authenticator. Maps are
// given as cborPairs to keep their order deterministic.
type cborPairs [][2]any

func cborEnc(v any) []byte {
	head := func(dst []byte, major byte, n uint64) []byte {
		switch {
		case n < 24:
			return append(dst, major<<5|byte(n))
		case n <= 0xff:
			return append(dst, major<<5|24, byte(n))
		case n <= 0xffff:
			return binary.BigEndian.AppendUint16(append(dst, major<<5|25), uint16(n))
		case n <= 0xffffffff:
			return binary.BigEndian.AppendUint32(append(dst, major<<5|26), uint32(n))
		}
		return binary.BigEndian.AppendUint64(append(dst, major<<5|27), n)
	}
	switch v := v.(type) {
	case int:
		if v < 0 {
			return head(nil, 1, uint64(-1-v))
		}
		return head(nil, 0, uint64(v))
	case Algorithm:
		return cborEnc(int(v))
	case []byte:
		return append(head(nil, 2, uint64(len(v))), v...)
	case string:
		return append(head(nil, 3, uint64(len(v))), v...)
	case []any:
		out := head(nil, 4, uint64(len(v)))
		for _, e := range v {
			out = append(out, cborEnc(e)...)
		}
		return out
	case cborPairs:
		out := head(nil, 5, uint64(len(v)))
		for _, p := range v {
			out = append(out, cborEnc(p[0])...)
			out = append(out, cborEnc(p[1])...)
		}
		return out
	case bool:
		if v {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	}
	panic("cborEnc: unsupported type")
}

// memStore is an in-memory CredentialStore.
type memStore struct {
	mu        sync.Mutex
	creds     map[string]Credential
	lookupErr error
	updateErr error
}

func newMemStore() *memStore { return &memStore{creds: map[string]Credential{}} }

func (s *memStore) LookupCredential(_ context.Context, id []byte) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lookupErr != nil {
		return Credential{}, s.lookupErr
	}
	c, ok := s.creds[string(id)]
	if !ok {
		return Credential{}, ErrCredentialNotFound
	}
	return c, nil
}

func (s *memStore) UpdateCredential(_ context.Context, c Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updateErr != nil {
		return s.updateErr
	}
	s.creds[string(c.ID)] = c
	return nil
}

func (s *memStore) put(c Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[string(c.ID)] = c
}

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func newTestRP(t testing.TB, cfg Config, store CredentialStore) *RelyingParty {
	t.Helper()
	if cfg.RPID == "" {
		cfg.RPID = "example.org"
	}
	if cfg.Origins == nil {
		cfg.Origins = []string{"https://example.org"}
	}
	rp, err := New(cfg, store, WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

// softAuthenticator is a software ES256 authenticator. Its fields are the
// inputs of the next response and can be changed by tests to build
// invalid responses.
type softAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte

	// Client data.
	typ         string
	origin      string
	crossOrigin bool
	topOrigin   string
	challenge   []byte // overrides the ceremony challenge when set
	// Authenticator data.
	rpID      string
	flags     byte
	signCount uint32
	aaguid    [16]byte
	// Response.
	userHandle []byte
	rawID      []byte // overrides credID in id/rawId when set
	corruptSig bool
	format     string
	attStmt    cborPairs
	trailing   []byte // appended to authenticator data
	clientExt  map[string]any
}

func newSoftAuthenticator(t testing.TB) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return &softAuthenticator{key: key, credID: id, origin: "https://example.org", rpID: "example.org", flags: flagUP | flagUV, format: "none"}
}

func (a *softAuthenticator) coseKey() []byte {
	pt, _ := a.key.PublicKey.Bytes()
	return cborEnc(cborPairs{{1, 2}, {3, -7}, {-1, 1}, {-2, pt[1:33]}, {-3, pt[33:]}})
}

func (a *softAuthenticator) clientData(def string, ch []byte) []byte {
	typ := def
	if a.typ != "" {
		typ = a.typ
	}
	if a.challenge != nil {
		ch = a.challenge
	}
	cd := map[string]any{"type": typ, "challenge": b64.EncodeToString(ch), "origin": a.origin, "crossOrigin": a.crossOrigin}
	if a.topOrigin != "" {
		cd["topOrigin"] = a.topOrigin
	}
	b, _ := json.Marshal(cd)
	return b
}

func (a *softAuthenticator) authData(attested bool) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	flags := a.flags
	if attested {
		flags |= flagAT
	}
	out := append(h[:], flags)
	out = binary.BigEndian.AppendUint32(out, a.signCount)
	if attested {
		out = append(out, a.aaguid[:]...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
		out = append(out, a.credID...)
		out = append(out, a.coseKey()...)
	}
	return append(out, a.trailing...)
}

func (a *softAuthenticator) id() []byte {
	if a.rawID != nil {
		return a.rawID
	}
	return a.credID
}

func (a *softAuthenticator) sign(msg []byte) []byte {
	h := sha256.Sum256(msg)
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, h[:])
	if a.corruptSig {
		sig[len(sig)-1] ^= 1
	}
	return sig
}

func (a *softAuthenticator) create(ch Challenge) []byte {
	return buildCreate(a, a.clientData(ceremonyCreate, ch.Value), a.authData(true))
}

func buildCreate(a *softAuthenticator, cd, ad []byte) []byte {
	stmt := a.attStmt
	if stmt == nil {
		stmt = cborPairs{}
	}
	att := cborEnc(cborPairs{{"fmt", a.format}, {"attStmt", stmt}, {"authData", ad}})
	b, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.id()), "rawId": b64.EncodeToString(a.id()), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"usb", "usb", "bogus"},
		},
		"clientExtensionResults":  a.clientExtensionResults(),
		"authenticatorAttachment": "cross-platform",
	})
	return b
}

func (a *softAuthenticator) clientExtensionResults() map[string]any {
	if a.clientExt == nil {
		return map[string]any{}
	}
	return a.clientExt
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func (a *softAuthenticator) get(ch Challenge) []byte {
	cd := a.clientData(ceremonyGet, ch.Value)
	ad := a.authData(false)
	cdh := sha256.Sum256(cd)
	sig := a.sign(slices.Concat(ad, cdh[:]))
	resp := map[string]any{
		"clientDataJSON":    b64.EncodeToString(cd),
		"authenticatorData": b64.EncodeToString(ad),
		"signature":         b64.EncodeToString(sig),
	}
	if a.userHandle != nil {
		resp["userHandle"] = b64.EncodeToString(a.userHandle)
	}
	b, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.id()), "rawId": b64.EncodeToString(a.id()), "type": "public-key",
		"response": resp, "clientExtensionResults": a.clientExtensionResults(),
	})
	return b
}

var testUser = User{Subject: "u-1", Handle: []byte("handle-1"), Name: "alice@example.org", DisplayName: "Alice"}

// register runs a registration with a and stores the credential.
func register(t testing.TB, rp *RelyingParty, store *memStore, a *softAuthenticator) Credential {
	t.Helper()
	_, ch, err := rp.BeginRegistration(testUser, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := rp.FinishRegistration(context.Background(), ch, a.create(ch))
	if err != nil {
		t.Fatalf("FinishRegistration = %v", err)
	}
	store.put(reg.Credential)
	return reg.Credential
}
