package webauthn

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	rp := newTestRP(t, Config{}, store)
	a := newSoftAuthenticator(t)
	a.flags |= flagBE

	cred := register(t, rp, store, a)
	if !bytes.Equal(cred.ID, a.credID) || cred.Subject != "u-1" || !bytes.Equal(cred.UserHandle, testUser.Handle) ||
		cred.Algorithm != ES256 || !cred.BackupEligible || cred.BackupState || !cred.UserVerified ||
		cred.AttestationType != AttestationNone || cred.AttestationFormat != "none" {
		t.Fatalf("unexpected credential %+v", cred)
	}
	if !slices.Equal(cred.Transports, []string{"usb"}) {
		t.Fatalf("transports = %v, want deduplicated known values", cred.Transports)
	}

	// Second factor login for a known user.
	_, ch, err := rp.BeginLogin([]Credential{cred})
	if err != nil {
		t.Fatal(err)
	}
	a.signCount = 5
	a.flags |= flagBS
	p, updated, err := rp.FinishLogin(ctx, ch, a.get(ch))
	if err != nil {
		t.Fatalf("FinishLogin = %v", err)
	}
	if p.Subject != "u-1" || p.Method != authent.MethodWebAuthn || !p.AuthTime.Equal(testNow) ||
		p.Claims["user_verified"] != true || p.Claims["credential_id"] != b64.EncodeToString(cred.ID) {
		t.Fatalf("unexpected principal %+v", p)
	}
	if updated.SignCount != 5 || !updated.BackupState {
		t.Fatalf("credential not updated: %+v", updated)
	}
	if stored, _ := store.LookupCredential(ctx, cred.ID); stored.SignCount != 5 || !stored.BackupState {
		t.Fatalf("store not updated: %+v", stored)
	}

	// Discoverable login: the user handle identifies the account.
	_, ch, err = rp.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	a.signCount = 6
	a.userHandle = testUser.Handle
	if p, _, err := rp.FinishLogin(ctx, ch, a.get(ch)); err != nil || p.Subject != "u-1" {
		t.Fatalf("discoverable FinishLogin = %+v, %v", p, err)
	}
}

func TestChallengeJSONRoundTrip(t *testing.T) {
	store := newMemStore()
	rp := newTestRP(t, Config{}, store)
	a := newSoftAuthenticator(t)
	_, ch, _ := rp.BeginRegistration(testUser, nil)
	data, err := json.Marshal(ch)
	if err != nil {
		t.Fatal(err)
	}
	var back Challenge
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if _, err := rp.FinishRegistration(context.Background(), back, a.create(ch)); err != nil {
		t.Fatalf("FinishRegistration after JSON round trip = %v", err)
	}
}

func TestRegistrationRejections(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		cfg    Config
		modify func(a *softAuthenticator, ch *Challenge)
		want   error
	}{
		{"wrong challenge", Config{}, func(a *softAuthenticator, _ *Challenge) { a.challenge = []byte("other") }, ErrChallenge},
		{"expired challenge", Config{}, func(_ *softAuthenticator, ch *Challenge) { ch.ExpiresAt = testNow }, ErrChallenge},
		{"login challenge", Config{}, func(_ *softAuthenticator, ch *Challenge) { ch.Ceremony = ceremonyGet }, ErrChallenge},
		{"challenge without user", Config{}, func(_ *softAuthenticator, ch *Challenge) { ch.Subject = "" }, ErrChallenge},
		{"client data type", Config{}, func(a *softAuthenticator, _ *Challenge) { a.typ = ceremonyGet }, ErrMalformed},
		{"origin", Config{}, func(a *softAuthenticator, _ *Challenge) { a.origin = "https://evil.example" }, ErrOrigin},
		{"origin with trailing slash", Config{}, func(a *softAuthenticator, _ *Challenge) { a.origin = "https://example.org/" }, ErrOrigin},
		{"cross origin", Config{}, func(a *softAuthenticator, _ *Challenge) { a.crossOrigin = true }, ErrOrigin},
		{"RP ID", Config{}, func(a *softAuthenticator, _ *Challenge) { a.rpID = "evil.example" }, ErrRPID},
		{"user not present", Config{}, func(a *softAuthenticator, _ *Challenge) { a.flags &^= flagUP }, ErrUserNotPresent},
		{"user not verified", Config{UserVerification: UserVerificationRequired}, func(a *softAuthenticator, _ *Challenge) { a.flags &^= flagUV }, ErrUserNotVerified},
		{"backup state without eligibility", Config{}, func(a *softAuthenticator, _ *Challenge) { a.flags |= flagBS }, ErrMalformed},
		{"algorithm not allowed", Config{Algorithms: []Algorithm{EdDSA}}, func(*softAuthenticator, *Challenge) {}, ErrAlgorithm},
		{"rawId differs from authenticator data", Config{}, func(a *softAuthenticator, _ *Challenge) { a.rawID = []byte("other-id") }, ErrMalformed},
		{"trailing authenticator data", Config{}, func(a *softAuthenticator, _ *Challenge) { a.trailing = []byte{0} }, ErrMalformed},
		{"none with statement", Config{}, func(a *softAuthenticator, _ *Challenge) { a.attStmt = cborPairs{{"sig", []byte{1}}} }, ErrAttestation},
		{"unsupported format", Config{}, func(a *softAuthenticator, _ *Challenge) { a.format = "tpm" }, ErrAttestation},
		{"self attestation with bad signature", Config{}, func(a *softAuthenticator, _ *Challenge) {
			a.format = "packed"
			a.attStmt = cborPairs{{"alg", -7}, {"sig", []byte{0x30, 0}}}
		}, ErrAttestation},
		{"self attestation with another alg", Config{}, func(a *softAuthenticator, _ *Challenge) {
			a.format = "packed"
			a.attStmt = cborPairs{{"alg", -257}, {"sig", []byte{0x30, 0}}}
		}, ErrAttestation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp := newTestRP(t, tc.cfg, newMemStore())
			a := newSoftAuthenticator(t)
			_, ch, err := rp.BeginRegistration(testUser, nil)
			if err != nil {
				t.Fatal(err)
			}
			tc.modify(a, &ch)
			resp := a.create(ch)
			_, err = rp.FinishRegistration(ctx, ch, resp)
			if !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("FinishRegistration = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSelfAttestation(t *testing.T) {
	rp := newTestRP(t, Config{}, newMemStore())
	a := newSoftAuthenticator(t)
	_, ch, _ := rp.BeginRegistration(testUser, nil)
	// The self attestation signature covers authData and the client data
	// hash, which the response builder computes; build it by hand here.
	a.format = "packed"
	cd := a.clientData(ceremonyCreate, ch.Value)
	ad := a.authData(true)
	h := sha256Sum(cd)
	a.attStmt = cborPairs{{"alg", -7}, {"sig", a.sign(append(ad, h...))}}
	resp := buildCreate(a, cd, ad)
	c, err := rp.FinishRegistration(context.Background(), ch, resp)
	if err != nil || c.AttestationType != AttestationSelf {
		t.Fatalf("FinishRegistration = %+v, %v", c, err)
	}
}

func TestRegistrationRejectsMalformedJSON(t *testing.T) {
	rp := newTestRP(t, Config{}, newMemStore())
	a := newSoftAuthenticator(t)
	_, ch, _ := rp.BeginRegistration(testUser, nil)
	good := a.create(ch)
	id := b64.EncodeToString(a.credID)
	for name, resp := range map[string][]byte{
		"empty":           nil,
		"not JSON":        []byte("{"),
		"duplicate field": []byte(`{"id":"` + id + `","id":"` + id + `"}`),
		"wrong type":      bytes.Replace(good, []byte(`"public-key"`), []byte(`"password"`), 1),
		"id differs":      bytes.Replace(good, []byte(`"id":"`+id), []byte(`"id":"AAAA`), 1),
		"padded base64":   bytes.Replace(good, []byte(`"rawId":"`+id), []byte(`"rawId":"`+id+`=`), 1),
		"newline base64":  bytes.Replace(good, []byte(`"rawId":"`+id), []byte(`"rawId":"`+id[:4]+`\n`+id[4:]), 1),
		"too large":       append(good[:len(good)-1], []byte(`,"x":"`+strings.Repeat("a", maxResponseSize)+`"}`)...),
	} {
		if _, err := rp.FinishRegistration(context.Background(), ch, resp); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: FinishRegistration = %v, want ErrMalformed", name, err)
		}
	}
}

func TestRegistrationRejectsExistingCredential(t *testing.T) {
	store := newMemStore()
	rp := newTestRP(t, Config{}, store)
	a := newSoftAuthenticator(t)
	register(t, rp, store, a)
	_, ch, _ := rp.BeginRegistration(testUser, nil)
	if _, err := rp.FinishRegistration(context.Background(), ch, a.create(ch)); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("FinishRegistration = %v, want ErrCredentialExists", err)
	}
}

func TestLoginRejections(t *testing.T) {
	ctx := context.Background()
	other := Credential{ID: []byte("other-cred"), Subject: "u-2", UserHandle: []byte("handle-2")}
	for _, tc := range []struct {
		name         string
		cfg          Config
		discoverable bool
		modify       func(a *softAuthenticator, ch *Challenge, store *memStore)
		want         error
	}{
		{"bad signature", Config{}, false, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.corruptSig = true }, ErrInvalidSignature},
		{"wrong challenge", Config{}, false, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.challenge = []byte("x") }, ErrChallenge},
		{"expired challenge", Config{}, false, func(_ *softAuthenticator, ch *Challenge, _ *memStore) { ch.ExpiresAt = testNow.Add(-time.Second) }, ErrChallenge},
		{"registration challenge", Config{}, false, func(_ *softAuthenticator, ch *Challenge, _ *memStore) { ch.Ceremony = ceremonyCreate }, ErrChallenge},
		{"client data type", Config{}, false, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.typ = ceremonyCreate }, ErrMalformed},
		{"origin", Config{}, false, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.origin = "https://example.org.evil" }, ErrOrigin},
		{"RP ID", Config{}, false, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.rpID = "example.com" }, ErrRPID},
		{"user not present", Config{}, false, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.flags &^= flagUP }, ErrUserNotPresent},
		{"user not verified", Config{UserVerification: UserVerificationRequired}, false, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.flags &^= flagUV }, ErrUserNotVerified},
		{"attested data in assertion", Config{}, false, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.flags |= flagAT }, ErrMalformed},
		{"sign count not increased", Config{}, false, func(a *softAuthenticator, _ *Challenge, s *memStore) {
			c, _ := s.LookupCredential(ctx, a.credID)
			c.SignCount = 10
			s.put(c)
			a.signCount = 10
		}, ErrSignCount},
		{"sign count reset to zero", Config{}, false, func(a *softAuthenticator, _ *Challenge, s *memStore) {
			c, _ := s.LookupCredential(ctx, a.credID)
			c.SignCount = 10
			s.put(c)
			a.signCount = 0
		}, ErrSignCount},
		{"backup eligibility changed", Config{}, false, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.flags |= flagBE }, ErrCredentialRejected},
		{"not in allowCredentials", Config{}, false, func(_ *softAuthenticator, ch *Challenge, _ *memStore) { ch.AllowedCredentials = [][]byte{other.ID} }, ErrCredentialRejected},
		{"unknown credential", Config{}, true, func(a *softAuthenticator, _ *Challenge, _ *memStore) {
			a.credID = []byte("unknown")
			a.userHandle = testUser.Handle
		}, ErrCredentialRejected},
		{"credential of another user", Config{}, false, func(_ *softAuthenticator, ch *Challenge, _ *memStore) {
			ch.Subject, ch.UserHandle, ch.AllowedCredentials = other.Subject, other.UserHandle, nil
		}, ErrCredentialRejected},
		{"user handle mismatch", Config{}, false, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.userHandle = other.UserHandle }, ErrCredentialRejected},
		{"discoverable without user handle", Config{}, true, func(*softAuthenticator, *Challenge, *memStore) {}, ErrCredentialRejected},
		{"discoverable with another user's handle", Config{}, true, func(a *softAuthenticator, _ *Challenge, _ *memStore) { a.userHandle = other.UserHandle }, ErrCredentialRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			rp := newTestRP(t, tc.cfg, store)
			a := newSoftAuthenticator(t)
			cred := register(t, rp, store, a)
			store.put(other)

			var ch Challenge
			var err error
			if tc.discoverable {
				_, ch, err = rp.BeginDiscoverableLogin()
			} else {
				_, ch, err = rp.BeginLogin([]Credential{cred})
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.modify(a, &ch, store)
			_, _, err = rp.FinishLogin(ctx, ch, a.get(ch))
			if !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("FinishLogin = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestInfrastructureErrors(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	rp := newTestRP(t, Config{}, store)
	a := newSoftAuthenticator(t)
	cred := register(t, rp, store, a)

	check := func(name string, err error) {
		t.Helper()
		if err == nil || errors.Is(err, authent.ErrUnauthenticated) {
			t.Errorf("%s = %v, want an error not wrapping ErrUnauthenticated", name, err)
		}
	}

	_, ch, _ := rp.BeginLogin([]Credential{cred})
	store.lookupErr = errors.New("db down")
	_, _, err := rp.FinishLogin(ctx, ch, a.get(ch))
	check("lookup failure", err)
	_, rch, _ := rp.BeginRegistration(testUser, nil)
	_, err = rp.FinishRegistration(ctx, rch, newSoftAuthenticator(t).create(rch))
	check("registration lookup failure", err)
	store.lookupErr = nil

	store.updateErr = errors.New("db down")
	_, _, err = rp.FinishLogin(ctx, ch, a.get(ch))
	check("update failure", err)
	store.updateErr = nil

	broken := cred
	broken.PublicKey = []byte{0xa0}
	store.put(broken)
	_, _, err = rp.FinishLogin(ctx, ch, a.get(ch))
	check("unusable stored key", err)

	// A store that detects a racing login reports ErrSignCount.
	store.put(cred)
	store.updateErr = ErrSignCount
	a.signCount = 1
	if _, _, err := rp.FinishLogin(ctx, ch, a.get(ch)); !errors.Is(err, ErrSignCount) {
		t.Errorf("racing update = %v, want ErrSignCount", err)
	}
}

func TestBeginLogin(t *testing.T) {
	rp := newTestRP(t, Config{}, newMemStore())
	if _, _, err := rp.BeginLogin(nil); err == nil {
		t.Fatal("BeginLogin accepted no credentials")
	}
	a := Credential{ID: []byte("a"), Subject: "u-1", UserHandle: []byte("h1")}
	b := Credential{ID: []byte("b"), Subject: "u-2", UserHandle: []byte("h2")}
	if _, _, err := rp.BeginLogin([]Credential{a, b}); err == nil {
		t.Fatal("BeginLogin accepted credentials of different users")
	}
	if _, _, err := rp.BeginLogin([]Credential{{ID: []byte("c")}}); err == nil {
		t.Fatal("BeginLogin accepted a credential without user")
	}
}

func TestBeginRegistrationValidatesUser(t *testing.T) {
	rp := newTestRP(t, Config{}, newMemStore())
	for _, u := range []User{
		{Handle: []byte("h"), Name: "n"},
		{Subject: "s", Name: "n"},
		{Subject: "s", Handle: make([]byte, 65), Name: "n"},
		{Subject: "s", Handle: []byte("h")},
	} {
		if _, _, err := rp.BeginRegistration(u, nil); err == nil {
			t.Errorf("BeginRegistration(%+v) accepted", u)
		}
	}
}

func TestOptionsJSON(t *testing.T) {
	rp := newTestRP(t, Config{RPName: "Example", UserVerification: UserVerificationRequired, ResidentKey: ResidentKeyRequired}, newMemStore())
	existing := Credential{ID: []byte{0xfb, 0xff}, Transports: []string{"usb"}}
	opts, ch, err := rp.BeginRegistration(testUser, []Credential{existing})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	data, _ := json.Marshal(opts)
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"rp":                 map[string]any{"id": "example.org", "name": "Example"},
		"user":               map[string]any{"id": b64.EncodeToString(testUser.Handle), "name": "alice@example.org", "displayName": "Alice"},
		"challenge":          b64.EncodeToString(ch.Value),
		"pubKeyCredParams":   []any{map[string]any{"type": "public-key", "alg": -8.0}, map[string]any{"type": "public-key", "alg": -7.0}, map[string]any{"type": "public-key", "alg": -257.0}},
		"timeout":            300000.0,
		"excludeCredentials": []any{map[string]any{"type": "public-key", "id": "-_8", "transports": []any{"usb"}}},
		"authenticatorSelection": map[string]any{
			"residentKey": "required", "requireResidentKey": true, "userVerification": "required",
		},
		"attestation": "none",
	}
	if !jsonEqual(got, want) {
		t.Fatalf("CreationOptions JSON =\n%s", data)
	}
	if len(ch.Value) != 32 || !ch.ExpiresAt.Equal(testNow.Add(5*time.Minute)) {
		t.Fatalf("unexpected challenge %+v", ch)
	}

	ropts, rch, _ := rp.BeginDiscoverableLogin()
	data, _ = json.Marshal(ropts)
	got = nil
	json.Unmarshal(data, &got)
	want = map[string]any{
		"challenge": b64.EncodeToString(rch.Value), "timeout": 300000.0, "rpId": "example.org",
		"allowCredentials": []any{}, "userVerification": "required",
	}
	if !jsonEqual(got, want) {
		t.Fatalf("RequestOptions JSON =\n%s", data)
	}
	if bytes.Equal(rch.Value, ch.Value) {
		t.Fatal("challenges are not random")
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a, json.Deterministic(true))
	y, _ := json.Marshal(b, json.Deterministic(true))
	return bytes.Equal(x, y)
}

func TestNewValidatesConfig(t *testing.T) {
	store := newMemStore()
	if _, err := New(Config{RPID: "example.org", Origins: []string{"https://example.org"}}, nil); err == nil {
		t.Fatal("nil store accepted")
	}
	for _, cfg := range []Config{
		{RPID: "", Origins: []string{"https://example.org"}},
		{RPID: "Example.org", Origins: []string{"https://example.org"}},
		{RPID: "https://example.org", Origins: []string{"https://example.org"}},
		{RPID: "example.org"},
		{RPID: "example.org", Origins: []string{"http://example.org"}},
		{RPID: "example.org", Origins: []string{"https://example.org/"}},
		{RPID: "example.org", Origins: []string{"https://example.org/login"}},
		{RPID: "example.org", Origins: []string{"https://evil.example"}},
		{RPID: "example.org", Origins: []string{"https://notexample.org"}},
		{RPID: "example.org", Origins: []string{"https://EXAMPLE.org"}},
		{RPID: "example.org", Origins: []string{"https://example.org"}, UserVerification: "always"},
		{RPID: "example.org", Origins: []string{"https://example.org"}, ResidentKey: "maybe"},
		{RPID: "example.org", Origins: []string{"https://example.org"}, Attestation: "enterprise"},
		{RPID: "example.org", Origins: []string{"https://example.org"}, Algorithms: []Algorithm{-47}},
		{RPID: "example.org", Origins: []string{"https://example.org"}, Timeout: -1},
		{RPID: "example.org", Origins: []string{"https://example.org"}, AttestationRoots: x509.NewCertPool()},
		{RPID: "example.org", Origins: []string{androidOrigin("app") + "="}},
		{RPID: "example.org", Origins: []string{androidOriginPrefix + b64.EncodeToString([]byte("short"))}},
		{RPID: "example.org", Origins: []string{androidOriginPrefix}},
		{RPID: "example.org", Origins: []string{"android:apk-key-hash"}},
		{RPID: "example.org", Origins: []string{"https://example.org"}, RelatedOrigins: []string{"http://example.co.uk"}},
		{RPID: "example.org", Origins: []string{"https://example.org"}, RelatedOrigins: []string{"https://example.co.uk/"}},
		{RPID: "example.org", Origins: []string{"https://example.org"}, TopOrigins: []string{"example.com"}},
		{RPID: "example.org", Origins: []string{"https://example.org"}, TopOrigins: []string{androidOrigin("app")}},
	} {
		if _, err := New(cfg, store); err == nil {
			t.Errorf("New(%+v) accepted", cfg)
		}
	}
	for _, cfg := range []Config{
		{RPID: "example.org", Origins: []string{"https://example.org", "https://login.example.org:8443"}},
		{RPID: "localhost", Origins: []string{"http://localhost:8080"}},
		{RPID: "example.org", Origins: []string{"https://example.org", androidOrigin("app")},
			RelatedOrigins: []string{"https://example.co.uk"}, TopOrigins: []string{"https://example.com"}},
	} {
		if _, err := New(cfg, store); err != nil {
			t.Errorf("New(%+v) = %v", cfg, err)
		}
	}
}
