package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type mdsPKI struct {
	root, inter, leaf          *x509.Certificate
	rootKey, interKey, leafKey *ecdsa.PrivateKey
}

func newMDSPKI(t testing.TB, crlBase string) *mdsPKI {
	t.Helper()
	p := &mdsPKI{}
	p.rootKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.interKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issue := func(serial int64, cn string, ca bool, dp string, parent *x509.Certificate, parentKey, key *ecdsa.PrivateKey) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour),
			IsCA: ca, BasicConstraintsValid: true,
		}
		if ca {
			tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		if dp != "" {
			tmpl.CRLDistributionPoints = []string{crlBase + dp}
		}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	p.root = issue(1, "MDS Root", true, "", nil, p.rootKey, p.rootKey)
	p.inter = issue(2, "MDS CA", true, "/root.crl", p.root, p.rootKey, p.interKey)
	p.leaf = issue(3, "mds.example", false, "/inter.crl", p.inter, p.interKey, p.leafKey)
	return p
}

func (p *mdsPKI) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	return pool
}

func newCRL(t testing.TB, issuer *x509.Certificate, key *ecdsa.PrivateKey, nextUpdate time.Time, revoked ...*x509.Certificate) *x509.RevocationList {
	t.Helper()
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: testNow.Add(-time.Hour), NextUpdate: nextUpdate}
	for _, c := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: testNow.Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	crl, _ := x509.ParseRevocationList(der)
	return crl
}

func (p *mdsPKI) crls(t testing.TB) []*x509.RevocationList {
	return []*x509.RevocationList{
		newCRL(t, p.root, p.rootKey, testNow.Add(time.Hour)),
		newCRL(t, p.inter, p.interKey, testNow.Add(time.Hour)),
	}
}

func b64std(c *x509.Certificate) string { return base64.StdEncoding.EncodeToString(c.Raw) }

func (p *mdsPKI) sign(header map[string]any, payload any) []byte {
	h, _ := json.Marshal(header)
	b, ok := payload.([]byte)
	if !ok {
		b, _ = json.Marshal(payload)
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(b)
	d := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, p.leafKey, d[:])
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return []byte(input + "." + b64.EncodeToString(sig))
}

func (p *mdsPKI) header() map[string]any {
	return map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []string{b64std(p.leaf), b64std(p.inter)}}
}

const testAAGUID = "f8a011f3-8c0a-4d15-8006-17111f9edc7d"

func mdsPayload(entries ...any) map[string]any {
	return map[string]any{"legalHeader": "test", "no": 7, "nextUpdate": "2026-07-01", "entries": entries}
}

func mdsEntry(aaguid string, roots []*x509.Certificate, reports ...map[string]any) map[string]any {
	var r []string
	for _, c := range roots {
		r = append(r, b64std(c))
	}
	if reports == nil {
		reports = []map[string]any{{"status": "FIDO_CERTIFIED_L1", "effectiveDate": "2025-01-01"}}
	}
	return map[string]any{
		"aaguid":            aaguid,
		"metadataStatement": map[string]any{"aaguid": aaguid, "description": "Test Key", "attestationRootCertificates": r},
		"statusReports":     reports,
	}
}

var atTestNow = WithMetadataClock(func() time.Time { return testNow })

func TestParseMetadata(t *testing.T) {
	p := newMDSPKI(t, "http://crl.example")
	ca := newTestCA(t)
	blob := p.sign(p.header(), mdsPayload(
		mdsEntry(testAAGUID, []*x509.Certificate{ca.cert}),
		map[string]any{"aaid": "4e4e#4005", "metadataStatement": map[string]any{}},
		map[string]any{"aaguid": "00000000-0000-0000-0000-000000000001", "statusReports": []any{}},
	))
	md, err := ParseMetadata(blob, p.roots(), WithCRLs(p.crls(t)...), atTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if md.Number() != 7 || !md.NextUpdate().Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("Number, NextUpdate = %d, %v", md.Number(), md.NextUpdate())
	}
	aaguid, _ := parseAAGUID(testAAGUID)
	e, ok := md.Lookup(aaguid)
	if !ok || e.Description != "Test Key" || len(e.AttestationRoots) != 1 || !e.AttestationRoots[0].Equal(ca.cert) ||
		len(e.StatusReports) != 1 || e.StatusReports[0].Status != "FIDO_CERTIFIED_L1" {
		t.Fatalf("Lookup = %+v, %v", e, ok)
	}
	if e, ok := md.Lookup([16]byte{15: 1}); !ok || len(e.AttestationRoots) != 0 {
		t.Fatalf("entry without a statement = %+v, %v", e, ok)
	}
	if _, ok := md.Lookup([16]byte{1}); ok {
		t.Fatal("Lookup found an unknown AAGUID")
	}
}

func TestParseMetadataRejects(t *testing.T) {
	p := newMDSPKI(t, "http://crl.example")
	other := newMDSPKI(t, "http://crl.example")
	good := mdsPayload(mdsEntry(testAAGUID, nil))
	with := func(k string, v any) map[string]any {
		h := p.header()
		h[k] = v
		return h
	}
	without := func(k string) map[string]any {
		h := p.header()
		delete(h, k)
		return h
	}
	crls := p.crls(t)
	rootCRL, interCRL := crls[0], crls[1]
	for _, tc := range []struct {
		name  string
		blob  []byte
		roots *x509.CertPool
		crls  []*x509.RevocationList
		now   time.Time
	}{
		{name: "bad signature", blob: func() []byte { b := p.sign(p.header(), good); b[len(b)-2] ^= 1; return b }()},
		{name: "signed by another key", blob: other.sign(p.header(), good)},
		{name: "untrusted root", blob: p.sign(p.header(), good), roots: other.roots()},
		{name: "expired chain", blob: p.sign(p.header(), good), now: testNow.Add(90 * time.Minute)},
		{name: "x5u header", blob: p.sign(with("x5u", "https://mds.example/chain"), good)},
		{name: "crit header", blob: p.sign(with("crit", []string{"exp"}), good)},
		{name: "jwk header", blob: p.sign(with("jwk", map[string]any{}), good)},
		{name: "alg none", blob: p.sign(with("alg", "none"), good)},
		{name: "RS256 with an EC key", blob: p.sign(with("alg", "RS256"), good)},
		{name: "no x5c", blob: p.sign(without("x5c"), good)},
		{name: "x5c in base64url", blob: p.sign(with("x5c", []string{b64.EncodeToString(p.leaf.Raw)}), good)},
		{name: "two parts", blob: []byte(strings.Join(strings.Split(string(p.sign(p.header(), good)), ".")[:2], "."))},
		{name: "no CRLs", blob: p.sign(p.header(), good), crls: []*x509.RevocationList{}},
		{name: "no CRL for the leaf", blob: p.sign(p.header(), good), crls: []*x509.RevocationList{rootCRL}},
		{name: "no CRL for the intermediate", blob: p.sign(p.header(), good), crls: []*x509.RevocationList{interCRL}},
		{name: "CRL from another issuer", blob: p.sign(p.header(), good), crls: []*x509.RevocationList{rootCRL, other.crls(t)[1]}},
		{name: "stale CRL", blob: p.sign(p.header(), good), crls: []*x509.RevocationList{rootCRL, newCRL(t, p.inter, p.interKey, testNow.Add(-time.Minute))}},
		{name: "revoked leaf", blob: p.sign(p.header(), good), crls: []*x509.RevocationList{rootCRL, newCRL(t, p.inter, p.interKey, testNow.Add(time.Hour), p.leaf)}},
		{name: "revoked intermediate", blob: p.sign(p.header(), good), crls: []*x509.RevocationList{newCRL(t, p.root, p.rootKey, testNow.Add(time.Hour), p.inter), interCRL}},
		{name: "payload not JSON", blob: p.sign(p.header(), []byte("{"))},
		{name: "payload without no", blob: p.sign(p.header(), map[string]any{"nextUpdate": "2026-07-01", "entries": []any{}})},
		{name: "payload with a bad nextUpdate", blob: p.sign(p.header(), map[string]any{"no": 1, "nextUpdate": "July", "entries": []any{}})},
		{name: "invalid AAGUID", blob: p.sign(p.header(), mdsPayload(mdsEntry("f8a011f38c0a4d15800617111f9edc7d", nil)))},
		{name: "duplicate AAGUID", blob: p.sign(p.header(), mdsPayload(mdsEntry(testAAGUID, nil), mdsEntry(testAAGUID, nil)))},
		{name: "statement is not an object", blob: p.sign(p.header(), mdsPayload(map[string]any{"aaguid": testAAGUID, "metadataStatement": 5}))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, c, now := p.roots(), crls, testNow
			if tc.roots != nil {
				roots = tc.roots
			}
			if tc.crls != nil {
				c = tc.crls
			}
			if !tc.now.IsZero() {
				now = tc.now
			}
			_, err := ParseMetadata(tc.blob, roots, WithCRLs(c...), WithMetadataClock(func() time.Time { return now }))
			if err == nil {
				t.Fatal("ParseMetadata accepted the BLOB")
			}
			if errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("BLOB error %v wraps ErrVerificationFailed", err)
			}
		})
	}
}

func TestMetadataRegistration(t *testing.T) {
	ca, otherCA := newTestCA(t), newTestCA(t)
	p := newMDSPKI(t, "http://crl.example")
	aaguid, _ := parseAAGUID(testAAGUID)
	unrelated := newTestCA(t).cert
	metadata := func(entries ...any) *Metadata {
		md, err := ParseMetadata(p.sign(p.header(), mdsPayload(entries...)), p.roots(), WithCRLs(p.crls(t)...), atTestNow)
		if err != nil {
			t.Fatal(err)
		}
		return md
	}
	report := func(status string, cert *x509.Certificate) map[string]any {
		r := map[string]any{"status": status}
		if cert != nil {
			r["certificate"] = b64std(cert)
		}
		return r
	}
	roots := []*x509.Certificate{ca.cert}
	for _, tc := range []struct {
		name       string
		md         *Metadata
		attRoots   *x509.CertPool
		attestNone bool
		ok         bool
	}{
		{name: "listed", md: metadata(mdsEntry(testAAGUID, roots)), ok: true},
		{name: "revoked", md: metadata(mdsEntry(testAAGUID, roots, report("FIDO_CERTIFIED", nil), report("REVOKED", nil)))},
		{name: "user verification bypass, then an update", md: metadata(mdsEntry(testAAGUID, roots, report("USER_VERIFICATION_BYPASS", nil), report("UPDATE_AVAILABLE", nil)))},
		{name: "user key compromise", md: metadata(mdsEntry(testAAGUID, roots, report("USER_KEY_REMOTE_COMPROMISE", nil)))},
		{name: "attestation key compromise of another batch", md: metadata(mdsEntry(testAAGUID, roots, report("ATTESTATION_KEY_COMPROMISE", unrelated))), ok: true},
		{name: "attestation key compromise of this batch", md: metadata(mdsEntry(testAAGUID, roots, report("ATTESTATION_KEY_COMPROMISE", ca.cert)))},
		{name: "compromise report with an unparsable certificate", md: metadata(mdsEntry(testAAGUID, roots, map[string]any{"status": "ATTESTATION_KEY_COMPROMISE", "certificate": "AAAA"}))},
		{name: "listed with another root", md: metadata(mdsEntry(testAAGUID, []*x509.Certificate{otherCA.cert}))},
		{name: "listed with another root, AttestationRoots trusts it", md: metadata(mdsEntry(testAAGUID, []*x509.Certificate{otherCA.cert})), attRoots: ca.pool()},
		{name: "not listed", md: metadata()},
		{name: "not listed, AttestationRoots trusts it", md: metadata(), attRoots: ca.pool(), ok: true},
		{name: "listed, no attestation", md: metadata(mdsEntry(testAAGUID, roots)), attestNone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp := newTestRP(t, Config{Attestation: ConveyanceDirect, Metadata: tc.md, AttestationRoots: tc.attRoots}, newMemStore())
			a := newSoftAuthenticator(t)
			a.aaguid = aaguid
			build := androidKeyStatement(t, ca, a, nil)
			format := "android-key"
			if tc.attestNone {
				build, format = func(_, _ []byte) cborPairs { return cborPairs{} }, "none"
			}
			_, err := registerAttested(t, rp, a, format, build)
			if tc.ok != (err == nil) || err != nil && !errors.Is(err, ErrAttestation) {
				t.Fatalf("FinishRegistration = %v, want ok=%v", err, tc.ok)
			}
		})
	}
	if _, err := New(Config{RPID: "example.org", Origins: []string{"https://example.org"}, Metadata: metadata()}, newMemStore()); err == nil {
		t.Fatal("New accepted Metadata without ConveyanceDirect")
	}
}

func TestFetchMetadata(t *testing.T) {
	var p *mdsPKI
	var blob []byte
	fail := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/blob":
			w.Write(blob)
		case "/root.crl":
			w.Write(newCRL(t, p.root, p.rootKey, testNow.Add(time.Hour)).Raw)
		case "/inter.crl":
			w.Write(newCRL(t, p.inter, p.interKey, testNow.Add(time.Hour)).Raw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	p = newMDSPKI(t, srv.URL)
	blob = p.sign(p.header(), mdsPayload(mdsEntry(testAAGUID, nil)))
	ctx := context.Background()

	md, err := FetchMetadata(ctx, srv.Client(), srv.URL+"/blob", p.roots(), atTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if aaguid, _ := parseAAGUID(testAAGUID); md.Number() != 7 || func() bool { _, ok := md.Lookup(aaguid); return !ok }() {
		t.Fatalf("FetchMetadata = %+v", md)
	}
	fail["/inter.crl"] = true
	if _, err := FetchMetadata(ctx, srv.Client(), srv.URL+"/blob", p.roots(), atTestNow); err == nil {
		t.Fatal("FetchMetadata accepted a BLOB whose CRL is unavailable")
	}
	fail["/blob"] = true
	if _, err := FetchMetadata(ctx, srv.Client(), srv.URL+"/blob", p.roots(), atTestNow); err == nil {
		t.Fatal("FetchMetadata accepted a failed download")
	}
	if _, err := FetchMetadata(ctx, nil, srv.URL+"/blob", p.roots(), atTestNow); err == nil {
		t.Fatal("FetchMetadata accepted a nil client")
	}
}

func FuzzMetadata(f *testing.F) {
	p := newMDSPKI(f, "http://crl.example")
	payload, _ := json.Marshal(mdsPayload(mdsEntry(testAAGUID, []*x509.Certificate{p.root}, map[string]any{"status": "REVOKED", "certificate": b64std(p.leaf)})))
	f.Add(payload)
	f.Add(p.sign(p.header(), payload))
	roots := p.roots()
	f.Fuzz(func(t *testing.T, data []byte) {
		parseMetadataPayload(data)
		verifyMetadataJWS(data, roots, testNow)
	})
}
