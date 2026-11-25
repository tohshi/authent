package password

import (
	"errors"
	"strings"
	"testing"
)

// testParams keeps the tests fast; production code uses DefaultParams.
var testParams = Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

func newTestHasher(t *testing.T) *Hasher {
	t.Helper()
	h, err := NewHasher(testParams)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHashAndVerify(t *testing.T) {
	h := newTestHasher(t)
	encoded, err := h.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("unexpected encoding: %s", encoded)
	}
	if err := h.Verify("correct horse", encoded); err != nil {
		t.Fatalf("Verify(correct) = %v", err)
	}
	if err := h.Verify("wrong horse", encoded); !errors.Is(err, ErrMismatch) {
		t.Fatalf("Verify(wrong) = %v, want ErrMismatch", err)
	}
}

func TestHashUsesRandomSalt(t *testing.T) {
	h := newTestHasher(t)
	a, _ := h.Hash("pw")
	b, _ := h.Hash("pw")
	if a == b {
		t.Fatal("two hashes of the same password are identical")
	}
}

// Independent vector computed with OpenSSL's Argon2 implementation:
//
//	openssl kdf -keylen 32 -kdfopt pass:password -kdfopt salt:somesalt \
//	  -kdfopt iter:2 -kdfopt memcost:65536 -kdfopt lanes:4 -binary ARGON2ID
const referenceHash = "$argon2id$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo"

func TestVerifyReferenceVector(t *testing.T) {
	h := newTestHasher(t)
	if err := h.Verify("password", referenceHash); err != nil {
		t.Fatalf("Verify(reference) = %v", err)
	}
}

func TestVerifyMalformed(t *testing.T) {
	h := newTestHasher(t)
	for _, encoded := range []string{
		"",
		"plain",
		"$argon2i$v=19$m=64,t=1,p=1$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
		"$argon2id$v=16$m=64,t=1,p=1$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
		"$argon2id$v=19$m=64,t=1$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
		"$argon2id$v=19$m=64,t=0,p=1$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
		"$argon2id$v=19$m=64,t=1,p=0$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
		"$argon2id$v=19$m=99999999999,t=1,p=1$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
		"$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHQ=$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
		"$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHQ$",
		"$argon2id$v=19$m=64,t=1,p=1$$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
		"$argon2id$v=19$m=64,t=1,p=1,x=1$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
		"$argon2id$v=19$t=1,m=64,p=1$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
		"$argon2id$v=19$m=64,t=1,p=1,norm=none$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
	} {
		if err := h.Verify("password", encoded); !errors.Is(err, ErrMalformedHash) {
			t.Errorf("Verify(%q) = %v, want ErrMalformedHash", encoded, err)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	h := newTestHasher(t)
	current, _ := h.Hash("pw")
	if needs, err := h.NeedsRehash(current); err != nil || needs {
		t.Fatalf("NeedsRehash(current) = %v, %v", needs, err)
	}
	if needs, err := h.NeedsRehash(referenceHash); err != nil || !needs {
		t.Fatalf("NeedsRehash(reference) = %v, %v", needs, err)
	}
	if _, err := h.NeedsRehash("junk"); !errors.Is(err, ErrMalformedHash) {
		t.Fatalf("NeedsRehash(junk) err = %v", err)
	}
}

func TestNewHasherRejectsWeakParams(t *testing.T) {
	for _, p := range []Params{
		{Memory: 0, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		{Memory: 64, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		{Memory: 64, Iterations: 1, Parallelism: 0, SaltLength: 16, KeyLength: 32},
		{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 4, KeyLength: 32},
		{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 8},
		{Memory: 4, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}, // m < 8*p
	} {
		if _, err := NewHasher(p); err == nil {
			t.Errorf("NewHasher(%+v) succeeded", p)
		}
	}
	if _, err := NewHasher(DefaultParams); err != nil {
		t.Errorf("NewHasher(DefaultParams) = %v", err)
	}
}
