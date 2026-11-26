package webauthn

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/tohshi/authent"
)

// specVectors are the WebAuthn Level 3 §16 test vectors, extracted by
// testdata/extract_spec_vectors.py.
type specVectors struct {
	AttestationCACert string `json:"attestation_ca_cert"`
	Vectors           []struct {
		Section        string            `json:"section"`
		Title          string            `json:"title"`
		Registration   map[string]string `json:"registration"`
		Authentication map[string]string `json:"authentication"`
	} `json:"vectors"`
}

func loadSpecVectors(t *testing.T) specVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/spec_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v specVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) != 15 {
		t.Fatalf("got %d vectors, want 15", len(v.Vectors))
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func specRegistrationJSON(t *testing.T, r map[string]string) []byte {
	id := b64.EncodeToString(unhex(t, r["credential_id"]))
	b, _ := json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(unhex(t, r["clientDataJSON"])),
			"attestationObject": b64.EncodeToString(unhex(t, r["attestationObject"])),
		},
	})
	return b
}

func specAuthenticationJSON(t *testing.T, credID []byte, a map[string]string) []byte {
	id := b64.EncodeToString(credID)
	b, _ := json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(unhex(t, a["clientDataJSON"])),
			"authenticatorData": b64.EncodeToString(unhex(t, a["authenticatorData"])),
			"signature":         b64.EncodeToString(unhex(t, a["signature"])),
		},
	})
	return b
}

var allAlgorithms = []Algorithm{ES256, ES384, ES512, EdDSA, RS256, PS256}

func TestSpecVectors(t *testing.T) {
	vs := loadSpecVectors(t)
	// The error each registration is expected to fail with; nil means the
	// registration and the following login must succeed.
	want := map[string]error{
		"16.4":  ErrOrigin,      // crossOrigin without topOrigin
		"16.5":  ErrOrigin,      // cross-origin iframe, but TopOrigins is empty
		"16.12": ErrAlgorithm,   // Ed448
		"16.13": ErrAttestation, // tpm
		"16.14": ErrAttestation, // android-key
		"16.15": ErrAttestation, // apple
	}
	ctx := context.Background()
	for _, v := range vs.Vectors {
		t.Run(v.Section, func(t *testing.T) {
			store := newMemStore()
			rp := newTestRP(t, Config{Algorithms: allAlgorithms}, store)
			reg := Challenge{
				Ceremony: ceremonyCreate, Value: unhex(t, v.Registration["challenge"]),
				ExpiresAt: testNow.Add(time.Minute), Subject: "u-1", UserHandle: []byte("handle-1"),
			}
			r, err := rp.FinishRegistration(ctx, reg, specRegistrationJSON(t, v.Registration))
			cred := r.Credential
			if w := want[v.Section]; w != nil {
				if !errors.Is(err, w) || !errors.Is(err, authent.ErrUnauthenticated) {
					t.Fatalf("%s: FinishRegistration = %v, want %v", v.Title, err, w)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: FinishRegistration = %v", v.Title, err)
			}
			if hex.EncodeToString(cred.ID) != v.Registration["credential_id"] || cred.Subject != "u-1" {
				t.Fatalf("unexpected credential %+v", cred)
			}
			store.put(cred)

			login := Challenge{
				Ceremony: ceremonyGet, Value: unhex(t, v.Authentication["challenge"]),
				ExpiresAt: testNow.Add(time.Minute), Subject: "u-1", UserHandle: []byte("handle-1"),
				AllowedCredentials: [][]byte{cred.ID},
			}
			l, err := rp.FinishLogin(ctx, login, specAuthenticationJSON(t, cred.ID, v.Authentication))
			p := l.Principal
			if err != nil {
				t.Fatalf("%s: FinishLogin = %v", v.Title, err)
			}
			if p.Subject != "u-1" || p.Method != authent.MethodWebAuthn {
				t.Fatalf("unexpected principal %+v", p)
			}

			// The login signature must not verify for another challenge.
			login.Value = unhex(t, v.Registration["challenge"])
			if _, err := rp.FinishLogin(ctx, login, specAuthenticationJSON(t, cred.ID, v.Authentication)); !errors.Is(err, ErrChallenge) {
				t.Fatalf("FinishLogin with another challenge = %v, want ErrChallenge", err)
			}
		})
	}
}

func TestSpecVectorsAttestationRoots(t *testing.T) {
	vs := loadSpecVectors(t)
	ca, err := x509.ParseCertificate(unhex(t, vs.AttestationCACert))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	want := map[string]AttestationType{
		"16.2":  "", // none: rejected
		"16.3":  "", // self: rejected
		"16.7":  AttestationBasic,
		"16.8":  AttestationBasic,
		"16.9":  AttestationBasic,
		"16.10": AttestationBasic,
		"16.11": AttestationBasic,
		"16.16": AttestationBasic,
	}
	for _, v := range vs.Vectors {
		w, ok := want[v.Section]
		if !ok {
			continue
		}
		t.Run(v.Section, func(t *testing.T) {
			rp := newTestRP(t, Config{Algorithms: allAlgorithms, Attestation: ConveyanceDirect, AttestationRoots: roots}, newMemStore())
			ch := Challenge{
				Ceremony: ceremonyCreate, Value: unhex(t, v.Registration["challenge"]),
				ExpiresAt: testNow.Add(time.Minute), Subject: "u-1", UserHandle: []byte("handle-1"),
			}
			r, err := rp.FinishRegistration(context.Background(), ch, specRegistrationJSON(t, v.Registration))
			cred := r.Credential
			if w == "" {
				if !errors.Is(err, ErrAttestation) {
					t.Fatalf("%s: FinishRegistration = %v, want ErrAttestation", v.Title, err)
				}
				return
			}
			if err != nil || cred.AttestationType != w {
				t.Fatalf("%s: FinishRegistration = %+v, %v", v.Title, cred, err)
			}
		})
	}

	// Without the root, the same attestations are rejected.
	rp := newTestRP(t, Config{Algorithms: allAlgorithms, Attestation: ConveyanceDirect, AttestationRoots: x509.NewCertPool()}, newMemStore())
	v := vs.Vectors[5] // 16.7
	ch := Challenge{
		Ceremony: ceremonyCreate, Value: unhex(t, v.Registration["challenge"]),
		ExpiresAt: testNow.Add(time.Minute), Subject: "u-1", UserHandle: []byte("handle-1"),
	}
	if _, err := rp.FinishRegistration(context.Background(), ch, specRegistrationJSON(t, v.Registration)); !errors.Is(err, ErrAttestation) {
		t.Fatalf("untrusted root = %v, want ErrAttestation", err)
	}
}
