package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

type testPKI struct {
	root, inter *x509.Certificate
	interKey    *ecdsa.PrivateKey
	roots       *x509.CertPool
}

func createCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func caTemplate(cn string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              testNow.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func newPKI(t *testing.T) testPKI {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := caTemplate("root", 1)
	root := createCert(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	inter := createCert(t, caTemplate("intermediate", 2), root, &interKey.PublicKey, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return testPKI{root: root, inter: inter, interKey: interKey, roots: roots}
}

// leaf issues a signing certificate for pub; edit adjusts the template.
func (p testPKI) leaf(t *testing.T, pub any, edit func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "signer"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if edit != nil {
		edit(tmpl)
	}
	return createCert(t, tmpl, p.inter, pub, p.interKey)
}

// reparse sends k through JSON, as keys from a JWK Set arrive.
func reparse(t *testing.T, k JWK) JWK {
	t.Helper()
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	return mustParseJWK(t, string(b))
}

func TestCertificateRoots(t *testing.T) {
	pki := newPKI(t)
	signer := ecSigner(t, "k")
	pub := &p256Key.PublicKey
	other := newPKI(t)
	tok, err := signer.Sign(validClaims())
	if err != nil {
		t.Fatal(err)
	}
	chain := func(edit func(*x509.Certificate)) []*x509.Certificate {
		return []*x509.Certificate{pki.leaf(t, pub, edit), pki.inter}
	}
	for name, tc := range map[string]struct {
		certs []*x509.Certificate
		roots *x509.CertPool
		ok    bool
	}{
		"valid chain":              {chain(nil), pki.roots, true},
		"no key usage extension":   {chain(func(c *x509.Certificate) { c.KeyUsage = 0 }), pki.roots, true},
		"untrusted root":           {chain(nil), other.roots, false},
		"leaf expired":             {chain(func(c *x509.Certificate) { c.NotAfter = testNow.Add(-time.Minute) }), pki.roots, false},
		"leaf not yet valid":       {chain(func(c *x509.Certificate) { c.NotBefore = testNow.Add(time.Minute) }), pki.roots, false},
		"leaf not for signing":     {chain(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }), pki.roots, false},
		"missing intermediate":     {[]*x509.Certificate{pki.leaf(t, pub, nil)}, pki.roots, false},
		"no x5c":                   {nil, pki.roots, false},
		"roots not required":       {nil, nil, true},
		"expired, roots not given": {chain(func(c *x509.Certificate) { c.NotAfter = testNow.Add(-time.Minute) }), nil, true},
	} {
		t.Run(name, func(t *testing.T) {
			key := reparse(t, JWK{KeyID: "k", Key: pub, Certificates: tc.certs})
			var opts []VerifierOption
			if tc.roots != nil {
				opts = append(opts, WithCertificateRoots(tc.roots))
			}
			_, err := newVerifier(t, NewStaticKeySet(key), opts...).Verify(context.Background(), tok)
			if tc.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrNoMatchingKey) {
				t.Fatalf("err = %v, want ErrNoMatchingKey", err)
			}
		})
	}
}

// A chain in the token's own x5c header must not make an unknown key
// trusted, even if it leads to the configured roots.
func TestX5CHeaderNeverUsed(t *testing.T) {
	pki := newPKI(t)
	trusted := reparse(t, JWK{KeyID: "k", Key: &p256Key.PublicKey,
		Certificates: []*x509.Certificate{pki.leaf(t, &p256Key.PublicKey, nil), pki.inter}})
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	header := map[string]any{"alg": "ES256", "kid": "k", "x5c": []string{
		base64.StdEncoding.EncodeToString(pki.leaf(t, &attacker.PublicKey, nil).Raw),
		base64.StdEncoding.EncodeToString(pki.inter.Raw),
	}}
	tok := forge(t, ES256, attacker, header, validPayload())
	v := newVerifier(t, NewStaticKeySet(trusted), WithCertificateRoots(pki.roots))
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestParseJWKChecksX5CLeaf(t *testing.T) {
	loadKeys(t)
	pki := newPKI(t)
	leaf := pki.leaf(t, &p256Key.PublicKey, nil)
	good := reparse(t, JWK{Key: &p256Key.PublicKey, Certificates: []*x509.Certificate{leaf, pki.inter}})
	if len(good.Certificates) != 2 || !good.Certificates[0].Equal(leaf) || !good.Certificates[1].Equal(pki.inter) {
		t.Fatalf("x5c not round-tripped: %v", good.Certificates)
	}

	pubJSON, _ := json.Marshal(JWK{Key: &p256Key.PublicKey})
	std := func(c *x509.Certificate) string { return base64.StdEncoding.EncodeToString(c.Raw) }
	bad := map[string][]string{
		"leaf for another key":   {std(pki.inter)},
		"intermediate first":     {std(pki.inter), std(leaf)},
		"base64url":              {base64.RawURLEncoding.EncodeToString(leaf.Raw) + "-_"},
		"not a certificate":      {"AAAA"},
		"not base64":             {"!!!!"},
		"valid leaf, bad second": {std(leaf), "AAAA"},
	}
	for name, x5c := range bad {
		in := withMembers(t, string(pubJSON), map[string]any{"x5c": x5c})
		if _, err := ParseJWK([]byte(in)); err == nil {
			t.Errorf("%s: ParseJWK succeeded", name)
		}
		if set, _ := ParseJWKSet([]byte(`{"keys":[` + in + `]}`)); len(set.Keys) != 0 {
			t.Errorf("%s: ParseJWKSet kept the key", name)
		}
	}
}

// Vector generated by testdata/gen_openssl_x5c.py with the openssl CLI.
func TestOpenSSLX5CVector(t *testing.T) {
	data, err := os.ReadFile("testdata/openssl_x5c.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec struct {
		Root  string         `json:"root"`
		JWK   map[string]any `json:"jwk"`
		Token string         `json:"token"`
	}
	if err := json.Unmarshal(data, &vec); err != nil {
		t.Fatal(err)
	}
	der, _ := base64.StdEncoding.DecodeString(vec.Root)
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	raw, _ := json.Marshal(vec.JWK)
	key := mustParseJWK(t, string(raw))
	leaf := key.Certificates[0]

	verifyAt := func(now time.Time, roots *x509.CertPool) error {
		v, err := NewVerifier(NewStaticKeySet(key), WithAlgorithms(ES256), WithIssuer(testIssuer),
			WithAudience("api"), WithCertificateRoots(roots), WithClock(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.Verify(context.Background(), vec.Token)
		return err
	}
	if err := verifyAt(leaf.NotBefore.Add(time.Hour), roots); err != nil {
		t.Fatalf("within validity: %v", err)
	}
	if err := verifyAt(leaf.NotAfter.Add(time.Hour), roots); !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("after expiry: err = %v", err)
	}
	if err := verifyAt(leaf.NotBefore.Add(time.Hour), newPKI(t).roots); !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("other roots: err = %v", err)
	}
}
