package webauthn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

// androidOrigin returns the origin of an Android app whose signing
// certificate is cert, in the form the Credential Manager documentation
// gives: "android:apk-key-hash:" and the unpadded base64url SHA-256 hash.
func androidOrigin(cert string) string {
	return androidOriginPrefix + b64.EncodeToString(sha256Sum([]byte(cert)))
}

func TestOrigins(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Origins:        []string{"https://example.org", androidOrigin("app")},
		RelatedOrigins: []string{"https://example.co.uk"},
		TopOrigins:     []string{"https://embedder.example"},
	}
	for _, tc := range []struct {
		name   string
		modify func(a *softAuthenticator)
		want   error
	}{
		{"RP origin", func(*softAuthenticator) {}, nil},
		{"Android app", func(a *softAuthenticator) { a.origin = androidOrigin("app") }, nil},
		{"related origin", func(a *softAuthenticator) { a.origin = "https://example.co.uk" }, nil},
		{"iframe in an allowed page", func(a *softAuthenticator) { a.crossOrigin, a.topOrigin = true, "https://embedder.example" }, nil},
		{"unlisted origin", func(a *softAuthenticator) { a.origin = "https://example.de" }, ErrOrigin},
		{"another Android app", func(a *softAuthenticator) { a.origin = androidOrigin("other") }, ErrOrigin},
		{"iframe in another page", func(a *softAuthenticator) { a.crossOrigin, a.topOrigin = true, "https://evil.example" }, ErrOrigin},
		{"iframe in a related origin page", func(a *softAuthenticator) { a.crossOrigin, a.topOrigin = true, "https://example.co.uk" }, ErrOrigin},
		{"iframe without topOrigin", func(a *softAuthenticator) { a.crossOrigin = true }, ErrOrigin},
		{"topOrigin without crossOrigin", func(a *softAuthenticator) { a.topOrigin = "https://embedder.example" }, ErrOrigin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			rp := newTestRP(t, cfg, store)
			a := newSoftAuthenticator(t)
			cred := register(t, rp, store, a)
			tc.modify(a)

			_, ch, err := rp.BeginLogin([]Credential{cred})
			if err != nil {
				t.Fatal(err)
			}
			a.signCount = 1
			if _, _, err := rp.FinishLogin(ctx, ch, a.get(ch)); !errors.Is(err, tc.want) || (err != nil && !errors.Is(err, authent.ErrUnauthenticated)) {
				t.Fatalf("FinishLogin = %v, want %v", err, tc.want)
			}

			b := newSoftAuthenticator(t)
			tc.modify(b)
			_, ch, err = rp.BeginRegistration(testUser, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rp.FinishRegistration(ctx, ch, b.create(ch)); !errors.Is(err, tc.want) {
				t.Fatalf("FinishRegistration = %v, want %v", err, tc.want)
			}
		})
	}
}

// The §16.5 vector comes from an iframe in https://example.com. The §16.4
// vector reports crossOrigin without topOrigin, so the embedding page is
// unknown and the response is rejected even with TopOrigins set.
func TestSpecVectorsTopOrigin(t *testing.T) {
	vs := loadSpecVectors(t)
	ctx := context.Background()
	for _, v := range vs.Vectors {
		if v.Section != "16.4" && v.Section != "16.5" {
			continue
		}
		t.Run(v.Section, func(t *testing.T) {
			store := newMemStore()
			rp := newTestRP(t, Config{TopOrigins: []string{"https://example.com"}}, store)
			reg := Challenge{
				Ceremony: ceremonyCreate, Value: unhex(t, v.Registration["challenge"]),
				ExpiresAt: testNow.Add(time.Minute), Subject: "u-1", UserHandle: []byte("handle-1"),
			}
			cred, err := rp.FinishRegistration(ctx, reg, specRegistrationJSON(t, v.Registration))
			if v.Section == "16.4" {
				if !errors.Is(err, ErrOrigin) {
					t.Fatalf("FinishRegistration = %v, want ErrOrigin", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("FinishRegistration = %v", err)
			}
			store.put(cred)
			login := Challenge{
				Ceremony: ceremonyGet, Value: unhex(t, v.Authentication["challenge"]),
				ExpiresAt: testNow.Add(time.Minute), Subject: "u-1", UserHandle: []byte("handle-1"),
			}
			if _, _, err := rp.FinishLogin(ctx, login, specAuthenticationJSON(t, cred.ID, v.Authentication)); err != nil {
				t.Fatalf("FinishLogin = %v", err)
			}
		})
	}
}
