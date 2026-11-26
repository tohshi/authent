package password

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

type legacyVector struct {
	Source   string `json:"source"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
}

func loadLegacyVectors(t testing.TB) []legacyVector {
	t.Helper()
	data, err := os.ReadFile("testdata/legacy_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []legacyVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func TestVerifyLegacyVectors(t *testing.T) {
	h := newTestHasher(t)
	schemes := map[string]bool{}
	for _, v := range loadLegacyVectors(t) {
		scheme, _, _ := strings.Cut(strings.TrimPrefix(v.Hash, "$"), "$")
		schemes[scheme] = true
		if err := h.Verify(v.Password, v.Hash); err != nil {
			t.Errorf("%s: Verify(%q, %q) = %v", v.Source, v.Password, v.Hash, err)
		}
		if err := h.Verify(v.Password+"x", v.Hash); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: wrong password: %v", v.Source, err)
		}
		if nfc := norm.NFC.String(v.Password); nfc != v.Password {
			if err := h.Verify(nfc, v.Hash); !errors.Is(err, ErrMismatch) {
				t.Errorf("%s: legacy hash matched the NFC form: %v", v.Source, err)
			}
		}
		if needs, err := h.NeedsRehash(v.Hash); err != nil || !needs {
			t.Errorf("%s: NeedsRehash = %v, %v; want true", v.Source, needs, err)
		}
	}
	for _, want := range []string{"2a", "2b", "2y", "scrypt:1024:8:1", "pbkdf2_sha256"} {
		if !schemes[want] {
			t.Errorf("no vector for %s", want)
		}
	}
}

func TestVerifyLegacyRejectsMalformed(t *testing.T) {
	const (
		bcryptBody = "Prdz0770Nsm/lnTairfMbOWYXKWxntmriGMhQ1QtqW0EPWeiSrJre"
		hexKey     = "1eb96390101198058fabc823c2828ec6bb16f20367ace5825029b0df37add0f9eddd1289e16f1150b09f87e13ebf8efc4b34054a1d160535f3dd08a5363d1444"
		b64Key     = "Lb+TCkRNEJYd+JofL7BseXb3wBrVS2/o9XKL1RHIUf8="
	)
	h := newTestHasher(t)
	for name, encoded := range map[string]string{
		"bcrypt $2x$ (crypt_blowfish bug variant)": "$2x$05$" + bcryptBody,
		"bcrypt without minor version":             "$2$05$" + bcryptBody,
		"pbkdf2 key with a line break":             "pbkdf2_sha256$1000$salt0Django0$" + b64Key[:20] + "\n" + b64Key[20:],
		"bcrypt cost below minimum":                "$2b$03$" + bcryptBody,
		"bcrypt cost above bound":                  "$2b$17$" + bcryptBody,
		"bcrypt cost 31":                           "$2b$31$" + bcryptBody,
		"bcrypt signed cost":                       "$2b$+5$" + bcryptBody,
		"bcrypt too long":                          "$2b$05$" + bcryptBody + "A",
		"bcrypt too short":                         "$2b$05$" + bcryptBody[1:],
		"bcrypt invalid character":                 "$2b$05$" + bcryptBody[1:] + "-",
		"bcrypt missing separator":                 "$2b$05" + bcryptBody + "A",

		"scrypt uppercase hex":            "scrypt:1024:8:1$salt0Werkzeug0$" + strings.ToUpper(hexKey),
		"scrypt N not a power of two":     "scrypt:1000:8:1$salt0Werkzeug0$" + hexKey,
		"scrypt N too small":              "scrypt:1:8:1$salt0Werkzeug0$" + hexKey,
		"scrypt 2 GiB of memory":          "scrypt:2097152:8:1$salt0Werkzeug0$" + hexKey,
		"scrypt 512 MiB of memory":        "scrypt:2097152:2:1$salt0Werkzeug0$" + hexKey,
		"scrypt V under cap, B over":      "scrypt:2:2:1048576$salt0Werkzeug0$" + hexKey,
		"scrypt N·r·p above work bound":   "scrypt:1024:8:4096$salt0Werkzeug0$" + hexKey,
		"scrypt r zero":                   "scrypt:1024:0:1$salt0Werkzeug0$" + hexKey,
		"scrypt p zero":                   "scrypt:1024:8:0$salt0Werkzeug0$" + hexKey,
		"scrypt leading zero":             "scrypt:01024:8:1$salt0Werkzeug0$" + hexKey,
		"scrypt signed N":                 "scrypt:+1024:8:1$salt0Werkzeug0$" + hexKey,
		"scrypt missing argument":         "scrypt:1024:8$salt0Werkzeug0$" + hexKey,
		"scrypt extra argument":           "scrypt:1024:8:1:1$salt0Werkzeug0$" + hexKey,
		"scrypt empty salt":               "scrypt:1024:8:1$$" + hexKey,
		"scrypt salt outside alphabet":    "scrypt:1024:8:1$salt-Werkzeug0$" + hexKey,
		"scrypt short key":                "scrypt:1024:8:1$salt0Werkzeug0$" + hexKey[:30],
		"scrypt odd hex length":           "scrypt:1024:8:1$salt0Werkzeug0$" + hexKey + "0",
		"scrypt extra field":              "scrypt:1024:8:1$salt0Werkzeug0$" + hexKey + "$",
		"Werkzeug PBKDF2 (not supported)": "pbkdf2:sha256:1000$salt0Werkzeug0$" + hexKey,

		"PBKDF2 zero iterations":        "pbkdf2_sha256$0$salt0Django0$" + b64Key,
		"PBKDF2 iterations above bound": "pbkdf2_sha256$10000001$salt0Django0$" + b64Key,
		"PBKDF2 leading zero":           "pbkdf2_sha256$01000$salt0Django0$" + b64Key,
		"PBKDF2 unpadded key":           "pbkdf2_sha256$1000$salt0Django0$" + strings.TrimSuffix(b64Key, "="),
		"PBKDF2 31-byte key":            "pbkdf2_sha256$1000$salt0Django0$" + b64Key[:40] + "AA==",
		"PBKDF2 extra field":            "pbkdf2_sha256$1000$salt0Django0$" + b64Key + "$",
		"PBKDF2 empty salt":             "pbkdf2_sha256$1000$$" + b64Key,
		"PBKDF2 SHA-1 (not supported)":  "pbkdf2_sha1$1000$salt0Django0$" + b64Key,
		"PBKDF2 missing key":            "pbkdf2_sha256$1000$salt0Django0",
	} {
		if err := h.Verify("password", encoded); !errors.Is(err, ErrMalformedHash) {
			t.Errorf("%s: Verify(%q) = %v, want ErrMalformedHash", name, encoded, err)
		}
		if _, err := h.NeedsRehash(encoded); !errors.Is(err, ErrMalformedHash) {
			t.Errorf("%s: NeedsRehash(%q) = %v, want ErrMalformedHash", name, encoded, err)
		}
	}
}

func TestAuthenticateUpgradesLegacyHash(t *testing.T) {
	h := newTestHasher(t)
	for _, v := range loadLegacyVectors(t) {
		store := &fakeStore{
			creds:   map[string]Credential{"alice": {Subject: "u-1", Hash: v.Hash}},
			updated: map[string]string{},
		}
		a, err := NewAuthenticator(store, h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Authenticate(context.Background(), "alice", v.Password); err != nil {
			t.Fatalf("%s: Authenticate = %v", v.Source, err)
		}
		upgraded, ok := store.updated["u-1"]
		if !ok {
			t.Fatalf("%s: legacy hash was not upgraded", v.Source)
		}
		if needs, err := h.NeedsRehash(upgraded); err != nil || needs || !strings.HasPrefix(upgraded, "$argon2id$") {
			t.Fatalf("%s: upgraded hash %q is not current", v.Source, upgraded)
		}
		if err := h.Verify(v.Password, upgraded); err != nil {
			t.Fatalf("%s: upgraded hash does not verify: %v", v.Source, err)
		}
		if nfc := norm.NFC.String(v.Password); nfc != v.Password {
			if err := h.Verify(nfc, upgraded); !errors.Is(err, ErrMismatch) {
				t.Fatalf("%s: upgraded hash started normalizing: %v", v.Source, err)
			}
		}
	}
}

func FuzzParseHash(f *testing.F) {
	for _, v := range loadLegacyVectors(f) {
		f.Add(v.Hash)
	}
	f.Add(referenceHash)
	f.Add(pepperedReferenceHash)
	f.Add("$argon2id$v=19$m=64,t=1,p=1,keyid=k2$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo")
	h, err := NewHasher(testParams, WithPepper("k1", pepper1))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		s, err := h.parse(encoded)
		if err != nil {
			if !errors.Is(err, ErrMalformedHash) && !errors.Is(err, ErrUnknownPepper) {
				t.Fatalf("parseHash(%q) = %v", encoded, err)
			}
			return
		}
		var ok bool
		switch s := s.(type) {
		case *argon2idHash:
			ok = s.params.validate() == nil && (s.keyID == "") == (s.pepper == nil)
		case *bcryptHash:
			ok = len(s.encoded) == 60
		case *werkzeugScryptHash:
			ok = scryptMemory(s.n, s.r, s.p) <= maxScryptMemoryBytes && s.n*s.r*s.p <= maxScryptWork
		case *djangoPBKDF2Hash:
			ok = s.iterations >= 1 && s.iterations <= maxPBKDF2Iterations
		}
		if !ok {
			t.Fatalf("parseHash(%q) accepted out-of-bounds parameters: %+v", encoded, s)
		}
	})
}
