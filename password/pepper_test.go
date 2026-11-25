package password

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tohshi/authent"
)

var (
	pepper1 = []byte("authent-test-pepper-key-32-bytes")
	pepper2 = []byte("another-test-pepper-key-32-bytes")
)

func newPepperedHasher(t *testing.T, opts ...HasherOption) *Hasher {
	t.Helper()
	h, err := NewHasher(testParams, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Independent vector for NFC normalization, then HMAC-SHA-256 under the
// pepper, then Argon2id, computed with OpenSSL:
//
//	MAC=$(printf 'caf\xc3\xa9' | openssl dgst -sha256 -mac HMAC \
//	  -macopt key:authent-test-pepper-key-32-bytes -hex | awk '{print $NF}')
//	openssl kdf -keylen 32 -kdfopt hexpass:$MAC -kdfopt salt:somesalt \
//	  -kdfopt iter:1 -kdfopt memcost:64 -kdfopt lanes:1 -binary ARGON2ID
const pepperedReferenceHash = "$argon2id$v=19$m=64,t=1,p=1,keyid=k1,norm=nfc$c29tZXNhbHQ$M3GmgWITVWFgadJ4yqU4PxdaK8BwEO27EKE/i2EM0qI"

func TestVerifyPepperedReferenceVector(t *testing.T) {
	h := newPepperedHasher(t, WithPepper("k1", pepper1))
	for _, pw := range []string{"café", "café"} {
		if err := h.Verify(pw, pepperedReferenceHash); err != nil {
			t.Fatalf("Verify(%q) = %v", pw, err)
		}
	}
	wrongKey := newPepperedHasher(t, WithPepper("k1", pepper2))
	if err := wrongKey.Verify("café", pepperedReferenceHash); !errors.Is(err, ErrMismatch) {
		t.Fatalf("Verify with another key under the same ID = %v, want ErrMismatch", err)
	}
}

func TestPepperHashAndVerify(t *testing.T) {
	h := newPepperedHasher(t, WithPepper("k1", pepper1))
	encoded, err := h.Hash("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=64,t=1,p=1,keyid=k1$") {
		t.Fatalf("unexpected encoding: %s", encoded)
	}
	if err := h.Verify("s3cret", encoded); err != nil {
		t.Fatalf("Verify(correct) = %v", err)
	}
	if err := h.Verify("wrong", encoded); !errors.Is(err, ErrMismatch) {
		t.Fatalf("Verify(wrong) = %v, want ErrMismatch", err)
	}
	if needs, err := h.NeedsRehash(encoded); err != nil || needs {
		t.Fatalf("NeedsRehash(current) = %v, %v", needs, err)
	}

	// Without the pepper the hash cannot be checked at all; it must not
	// fall back to verifying the unkeyed password.
	for _, other := range []*Hasher{
		newTestHasher(t),
		newPepperedHasher(t, WithPepper("k2", pepper2)),
	} {
		if err := other.Verify("s3cret", encoded); !errors.Is(err, ErrUnknownPepper) {
			t.Fatalf("Verify with unknown key ID = %v, want ErrUnknownPepper", err)
		}
		if _, err := other.NeedsRehash(encoded); !errors.Is(err, ErrUnknownPepper) {
			t.Fatalf("NeedsRehash with unknown key ID = %v, want ErrUnknownPepper", err)
		}
	}
}

func TestPepperRotation(t *testing.T) {
	old := newPepperedHasher(t, WithPepper("k1", pepper1))
	oldHash, _ := old.Hash("s3cret")
	plainHash, _ := newTestHasher(t).Hash("s3cret")

	rotated := newPepperedHasher(t, WithPepper("k2", pepper2), WithRetiredPepper("k1", pepper1))
	newHash, _ := rotated.Hash("s3cret")
	for _, tc := range []struct {
		name, encoded string
		needsRehash   bool
	}{
		{"retired pepper", oldHash, true},
		{"no pepper", plainHash, true},
		{"current pepper", newHash, false},
	} {
		if err := rotated.Verify("s3cret", tc.encoded); err != nil {
			t.Errorf("%s: Verify = %v", tc.name, err)
		}
		if needs, err := rotated.NeedsRehash(tc.encoded); err != nil || needs != tc.needsRehash {
			t.Errorf("%s: NeedsRehash = %v, %v; want %v", tc.name, needs, err, tc.needsRehash)
		}
	}

	// Dropping the pepper entirely: peppered hashes are upgraded to plain ones.
	unpeppered := newPepperedHasher(t, WithRetiredPepper("k1", pepper1))
	if needs, err := unpeppered.NeedsRehash(oldHash); err != nil || !needs {
		t.Fatalf("NeedsRehash(retired) = %v, %v; want true", needs, err)
	}
	if needs, err := unpeppered.NeedsRehash(plainHash); err != nil || needs {
		t.Fatalf("NeedsRehash(plain) = %v, %v; want false", needs, err)
	}
}

func TestAuthenticateRotatesPepper(t *testing.T) {
	old := newPepperedHasher(t, WithPepper("k1", pepper1))
	policy, _ := NewPolicy(1, 64, &stubBreachChecker{})
	oldHash, err := policy.Hash(context.Background(), old, "café")
	if err != nil {
		t.Fatal(err)
	}
	bcryptHash := loadLegacyVectors(t)[0]
	store := &fakeStore{
		creds: map[string]Credential{
			"alice": {Subject: "u-1", Hash: oldHash},
			"bob":   {Subject: "u-2", Hash: bcryptHash.Hash},
		},
		updated: map[string]string{},
	}
	h := newPepperedHasher(t, WithPepper("k2", pepper2), WithRetiredPepper("k1", pepper1))
	a, _ := NewAuthenticator(store, h)
	if _, err := a.Authenticate(context.Background(), "alice", "café"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(context.Background(), "bob", bcryptHash.Password); err != nil {
		t.Fatal(err)
	}
	if got := store.updated["u-1"]; !strings.Contains(got, ",keyid=k2,norm=nfc$") || h.Verify("café", got) != nil {
		t.Fatalf("rotated hash %q does not use k2 with NFC", got)
	}
	if got := store.updated["u-2"]; !strings.Contains(got, ",keyid=k2$") || h.Verify(bcryptHash.Password, got) != nil {
		t.Fatalf("upgraded legacy hash %q does not use k2", got)
	}
}

func TestAuthenticateUnknownPepperFailsClosed(t *testing.T) {
	encoded, _ := newPepperedHasher(t, WithPepper("k1", pepper1)).Hash("s3cret")
	store := &fakeStore{creds: map[string]Credential{"alice": {Subject: "u-1", Hash: encoded}}}
	a, _ := NewAuthenticator(store, newTestHasher(t))
	_, err := a.Authenticate(context.Background(), "alice", "s3cret")
	if !errors.Is(err, ErrUnknownPepper) || errors.Is(err, authent.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnknownPepper without ErrUnauthenticated", err)
	}
}

func TestNewHasherRejectsInvalidPepper(t *testing.T) {
	for name, opts := range map[string][]HasherOption{
		"short key":       {WithPepper("k1", pepper1[:31])},
		"empty ID":        {WithPepper("", pepper1)},
		"long ID":         {WithPepper(strings.Repeat("k", 17), pepper1)},
		"ID with comma":   {WithPepper("k,1", pepper1)},
		"ID with dollar":  {WithRetiredPepper("k$1", pepper1)},
		"duplicate ID":    {WithPepper("k1", pepper1), WithRetiredPepper("k1", pepper2)},
		"two current":     {WithPepper("k1", pepper1), WithPepper("k2", pepper2)},
		"nil option":      {nil},
		"short retired":   {WithRetiredPepper("k1", []byte("short"))},
		"non-ASCII ID":    {WithPepper("kë", pepper1)},
		"ID with equals":  {WithPepper("k=1", pepper1)},
		"ID with space":   {WithPepper("k 1", pepper1)},
		"ID with newline": {WithPepper("k1\n", pepper1)},
	} {
		if _, err := NewHasher(testParams, opts...); err == nil {
			t.Errorf("%s: NewHasher succeeded", name)
		}
	}
	if _, err := NewHasher(testParams, WithPepper(strings.Repeat("k", 16), pepper1)); err != nil {
		t.Errorf("16-character ID rejected: %v", err)
	}
}

func TestPepperKeyIsCopied(t *testing.T) {
	key := append([]byte(nil), pepper1...)
	h := newPepperedHasher(t, WithPepper("k1", key))
	encoded, _ := h.Hash("s3cret")
	key[0] ^= 1
	if err := h.Verify("s3cret", encoded); err != nil {
		t.Fatalf("caller's later write to the key changed the pepper: %v", err)
	}
}

func TestVerifyRejectsMalformedKeyID(t *testing.T) {
	h := newPepperedHasher(t, WithPepper("k1", pepper1))
	const tail = "$c29tZXNhbHQ$M3GmgWITVWFgadJ4yqU4PxdaK8BwEO27EKE/i2EM0qI"
	for _, costs := range []string{
		"m=64,t=1,p=1,norm=nfc,keyid=k1",
		"m=64,t=1,p=1,keyid=",
		"m=64,t=1,p=1,keyid=k1,keyid=k1",
		"m=64,t=1,p=1,keyid=k+1",
		"m=64,t=1,p=1,keyid=k1,norm=nfc,norm=nfc",
		"m=64,t=1,p=1,keyid=" + strings.Repeat("k", 17),
	} {
		encoded := "$argon2id$v=19$" + costs + tail
		if err := h.Verify("café", encoded); !errors.Is(err, ErrMalformedHash) {
			t.Errorf("Verify(%q) = %v, want ErrMalformedHash", encoded, err)
		}
	}
}
