package webauthn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"
)

type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t testing.TB) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Attestation Root"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{key: key, cert: cert}
}

func (ca *testCA) issue(t testing.TB, tmpl *x509.Certificate, pub crypto.PublicKey) []byte {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(2)
	tmpl.NotBefore, tmpl.NotAfter = testNow.Add(-time.Hour), testNow.Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (ca *testCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

func registerAttested(t *testing.T, rp *RelyingParty, a *softAuthenticator, format string, build func(cd, ad []byte) cborPairs) (Registration, error) {
	t.Helper()
	_, ch, err := rp.BeginRegistration(testUser, nil)
	if err != nil {
		t.Fatal(err)
	}
	cd := a.clientData(ceremonyCreate, ch.Value)
	ad := a.authData(true)
	a.format = format
	a.attStmt = build(cd, ad)
	return rp.FinishRegistration(context.Background(), ch, buildCreate(a, cd, ad))
}

type tpmParts struct {
	ver        string
	alg        Algorithm
	pubArea    []byte
	nameAlg    uint16
	name       []byte // derived from pubArea and nameAlg if nil
	magic      uint32
	typ        uint16
	extraData  []byte
	aik        *x509.Certificate
	corruptSig bool
}

func tpmECCPublic(k *ecdsa.PublicKey) []byte {
	pt, _ := k.Bytes()
	b := []byte{0x00, 0x23, 0x00, 0x0b, 0x00, 0x06, 0x04, 0x72, 0x00, 0x00, 0x00, 0x10, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x10, 0x00, 0x20}
	b = append(b, pt[1:33]...)
	return append(append(b, 0x00, 0x20), pt[33:]...)
}

func tpmCertInfo(magic uint32, typ uint16, extraData, name []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, magic)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = append(b, 0, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(extraData)))
	b = append(append(b, extraData...), make([]byte, 25)...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(name)))
	return append(append(b, name...), 0, 0)
}

func tpmSAN(attrs ...pkix.AttributeTypeAndValue) []byte {
	name, _ := asn1.Marshal(pkix.RDNSequence{attrs})
	san, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: name}})
	return san
}

var tpmDeviceAttributes = []pkix.AttributeTypeAndValue{
	{Type: oidTPMManufacturer, Value: "id:FFFFF1D0"}, {Type: oidTPMModel, Value: "test"}, {Type: oidTPMVersion, Value: "id:00010002"},
}

func aikTemplate() *x509.Certificate {
	return &x509.Certificate{
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: oidSubjectAltName, Critical: true, Value: tpmSAN(tpmDeviceAttributes...)}},
	}
}

func tpmStatement(t *testing.T, ca *testCA, a *softAuthenticator, modify func(*tpmParts)) func(cd, ad []byte) cborPairs {
	return func(cd, ad []byte) cborPairs {
		p := &tpmParts{
			ver: "2.0", alg: ES256, pubArea: tpmECCPublic(&a.key.PublicKey), nameAlg: tpmAlgSHA256,
			magic: tpmGeneratedValue, typ: tpmSTAttestCertify, extraData: sha256Sum(slices.Concat(ad, sha256Sum(cd))), aik: aikTemplate(),
		}
		if modify != nil {
			modify(p)
		}
		binary.BigEndian.PutUint16(p.pubArea[2:4], p.nameAlg)
		if p.name == nil {
			digest := sha256Sum(p.pubArea)
			if p.nameAlg == tpmAlgSHA1 {
				h := sha1.Sum(p.pubArea)
				digest = h[:]
			}
			p.name = append(binary.BigEndian.AppendUint16(nil, p.nameAlg), digest...)
		}
		certInfo := tpmCertInfo(p.magic, p.typ, p.extraData, p.name)
		aikKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der := ca.issue(t, p.aik, &aikKey.PublicKey)
		h := sha256.Sum256(certInfo)
		sig, _ := ecdsa.SignASN1(rand.Reader, aikKey, h[:])
		if p.corruptSig {
			sig[len(sig)-1] ^= 1
		}
		return cborPairs{{"ver", p.ver}, {"alg", p.alg}, {"x5c", []any{der}}, {"sig", sig}, {"certInfo", certInfo}, {"pubArea", p.pubArea}}
	}
}

func TestTPMAttestation(t *testing.T) {
	ca := newTestCA(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	aaguidExt, _ := asn1.Marshal(make([]byte, 16))
	otherAAGUID, _ := asn1.Marshal(slices.Repeat([]byte{0xff}, 16))
	for _, tc := range []struct {
		name   string
		modify func(*tpmParts)
		ok     bool
	}{
		{"valid", nil, true},
		{"valid with matching AAGUID extension", func(p *tpmParts) {
			p.aik.ExtraExtensions = append(p.aik.ExtraExtensions, pkix.Extension{Id: oidFIDOGenCeAAGUID, Value: aaguidExt})
		}, true},
		{"ver 1.0", func(p *tpmParts) { p.ver = "1.0" }, false},
		{"EdDSA", func(p *tpmParts) { p.alg = EdDSA }, false},
		{"pubArea of another key", func(p *tpmParts) { p.pubArea = tpmECCPublic(&other.PublicKey) }, false},
		{"pubArea with trailing bytes", func(p *tpmParts) { p.pubArea = append(p.pubArea, 0) }, false},
		{"pubArea with a symmetric algorithm", func(p *tpmParts) { p.pubArea[11] = 0x06 }, false},
		{"extraData of other data", func(p *tpmParts) { p.extraData = sha256Sum([]byte("other")) }, false},
		{"name of another object", func(p *tpmParts) {
			p.name = append([]byte{0x00, 0x0b}, sha256Sum(tpmECCPublic(&other.PublicKey))...)
		}, false},
		{"SHA-1 name", func(p *tpmParts) { p.nameAlg = tpmAlgSHA1 }, false},
		{"SHA-1 name algorithm and an empty name", func(p *tpmParts) { p.nameAlg, p.name = tpmAlgSHA1, []byte{} }, false},
		{"not TPM-generated", func(p *tpmParts) { p.magic = 0 }, false},
		{"quote instead of certification", func(p *tpmParts) { p.typ = 0x8018 }, false},
		{"AIK with a subject", func(p *tpmParts) { p.aik.Subject = pkix.Name{CommonName: "aik"} }, false},
		{"AIK without the AIK key usage", func(p *tpmParts) { p.aik.UnknownExtKeyUsage = nil }, false},
		{"AIK that is a CA", func(p *tpmParts) { p.aik.IsCA = true }, false},
		{"AIK without basic constraints", func(p *tpmParts) { p.aik.BasicConstraintsValid = false }, false},
		{"AIK without SAN", func(p *tpmParts) { p.aik.ExtraExtensions = nil }, false},
		{"AIK SAN without model", func(p *tpmParts) {
			p.aik.ExtraExtensions[0].Value = tpmSAN(tpmDeviceAttributes[0], tpmDeviceAttributes[2])
		}, false},
		{"AIK with another AAGUID", func(p *tpmParts) {
			p.aik.ExtraExtensions = append(p.aik.ExtraExtensions, pkix.Extension{Id: oidFIDOGenCeAAGUID, Value: otherAAGUID})
		}, false},
		{"bad signature", func(p *tpmParts) { p.corruptSig = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp := newTestRP(t, Config{}, newMemStore())
			a := newSoftAuthenticator(t)
			reg, err := registerAttested(t, rp, a, "tpm", tpmStatement(t, ca, a, tc.modify))
			if !tc.ok {
				if !errors.Is(err, ErrAttestation) {
					t.Fatalf("FinishRegistration = %v, want ErrAttestation", err)
				}
				return
			}
			if err != nil || reg.Credential.AttestationType != AttestationAttCA {
				t.Fatalf("FinishRegistration = %+v, %v", reg.Credential, err)
			}
		})
	}
}

type androidParts struct {
	challenge     []byte
	software, tee []byte
	certKey       crypto.PublicKey
	signer        *ecdsa.PrivateKey
	extension     bool
	trailing      []byte
}

func akField(tag int, inner []byte) []byte {
	b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner})
	return b
}

func akPurpose(p ...int) []byte {
	inner, _ := asn1.MarshalWithParams(p, "set")
	return akField(kmTagPurpose, inner)
}

func akOrigin(o int) []byte {
	inner, _ := asn1.Marshal(o)
	return akField(kmTagOrigin, inner)
}

func akAllApplications() []byte { return akField(kmTagAllApps, asn1.NullBytes) }

func akList(fields ...[]byte) []byte {
	b, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: slices.Concat(fields...)})
	return b
}

func keyDescriptionDER(challenge, software, tee []byte) []byte {
	b, _ := asn1.Marshal(struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeymasterVersion         int
		KeymasterSecurityLevel   asn1.Enumerated
		AttestationChallenge     []byte
		UniqueID                 []byte
		SoftwareEnforced         asn1.RawValue
		TEEEnforced              asn1.RawValue
	}{3, 1, 4, 1, challenge, []byte{}, asn1.RawValue{FullBytes: software}, asn1.RawValue{FullBytes: tee}})
	return b
}

func androidKeyStatement(t *testing.T, ca *testCA, a *softAuthenticator, modify func(*androidParts)) func(cd, ad []byte) cborPairs {
	return func(cd, ad []byte) cborPairs {
		p := &androidParts{
			challenge: sha256Sum(cd), software: akList(), tee: akList(akPurpose(kmPurposeSign), akOrigin(kmOriginGenerated)),
			certKey: &a.key.PublicKey, signer: a.key, extension: true,
		}
		if modify != nil {
			modify(p)
		}
		tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "Android Keystore Key"}}
		if p.extension {
			kd := append(keyDescriptionDER(p.challenge, p.software, p.tee), p.trailing...)
			tmpl.ExtraExtensions = []pkix.Extension{{Id: oidAndroidKeyDescription, Value: kd}}
		}
		der := ca.issue(t, tmpl, p.certKey)
		h := sha256.Sum256(slices.Concat(ad, sha256Sum(cd)))
		sig, _ := ecdsa.SignASN1(rand.Reader, p.signer, h[:])
		if a.corruptSig {
			sig[len(sig)-1] ^= 1
		}
		return cborPairs{{"alg", ES256}, {"sig", sig}, {"x5c", []any{der}}}
	}
}

func TestAndroidKeyAttestation(t *testing.T) {
	ca := newTestCA(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const kmPurposeDecrypt, kmOriginImported = 1, 2
	for _, tc := range []struct {
		name   string
		modify func(*androidParts)
		ok     bool
	}{
		{"valid", nil, true},
		{"valid across both lists", func(p *androidParts) {
			p.software, p.tee = akList(akPurpose(kmPurposeSign)), akList(akOrigin(kmOriginGenerated))
		}, true},
		{"challenge of other data", func(p *androidParts) { p.challenge = sha256Sum([]byte("other")) }, false},
		{"allApplications in teeEnforced", func(p *androidParts) {
			p.tee = akList(akPurpose(kmPurposeSign), akAllApplications(), akOrigin(kmOriginGenerated))
		}, false},
		{"allApplications in softwareEnforced", func(p *androidParts) { p.software = akList(akAllApplications()) }, false},
		{"imported key", func(p *androidParts) { p.tee = akList(akPurpose(kmPurposeSign), akOrigin(kmOriginImported)) }, false},
		{"imported key in softwareEnforced", func(p *androidParts) { p.software = akList(akOrigin(kmOriginImported)) }, false},
		{"no origin", func(p *androidParts) { p.tee = akList(akPurpose(kmPurposeSign)) }, false},
		{"decryption key", func(p *androidParts) { p.tee = akList(akPurpose(kmPurposeDecrypt), akOrigin(kmOriginGenerated)) }, false},
		{"signing and decryption key", func(p *androidParts) {
			p.tee = akList(akPurpose(kmPurposeSign, kmPurposeDecrypt), akOrigin(kmOriginGenerated))
		}, false},
		{"no purpose", func(p *androidParts) { p.tee = akList(akOrigin(kmOriginGenerated)) }, false},
		{"another attested key signs", func(p *androidParts) { p.certKey, p.signer = &other.PublicKey, other }, false},
		{"no key description", func(p *androidParts) { p.extension = false }, false},
		{"trailing data after the key description", func(p *androidParts) { p.trailing = []byte{0} }, false},
		{"authorization list is not a sequence", func(p *androidParts) { p.software = []byte{0x05, 0x00} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp := newTestRP(t, Config{}, newMemStore())
			a := newSoftAuthenticator(t)
			reg, err := registerAttested(t, rp, a, "android-key", androidKeyStatement(t, ca, a, tc.modify))
			if !tc.ok {
				if !errors.Is(err, ErrAttestation) {
					t.Fatalf("FinishRegistration = %v, want ErrAttestation", err)
				}
				return
			}
			if err != nil || reg.Credential.AttestationType != AttestationBasic {
				t.Fatalf("FinishRegistration = %+v, %v", reg.Credential, err)
			}
		})
	}

	rp := newTestRP(t, Config{}, newMemStore())
	a := newSoftAuthenticator(t)
	build := androidKeyStatement(t, ca, a, nil)
	a.corruptSig = true
	if _, err := registerAttested(t, rp, a, "android-key", build); !errors.Is(err, ErrAttestation) {
		t.Fatalf("bad signature: FinishRegistration = %v, want ErrAttestation", err)
	}
}

func appleNonceDER(nonce []byte) []byte {
	b, _ := asn1.Marshal(struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}{nonce})
	return b
}

func appleStatement(t *testing.T, ca *testCA, a *softAuthenticator, nonce func(cd, ad []byte) []byte, certKey crypto.PublicKey) func(cd, ad []byte) cborPairs {
	return func(cd, ad []byte) cborPairs {
		tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "credential"}}
		if nonce != nil {
			tmpl.ExtraExtensions = []pkix.Extension{{Id: oidAppleNonce, Value: appleNonceDER(nonce(cd, ad))}}
		}
		if certKey == nil {
			certKey = &a.key.PublicKey
		}
		return cborPairs{{"x5c", []any{ca.issue(t, tmpl, certKey)}}}
	}
}

func TestAppleAttestation(t *testing.T) {
	ca := newTestCA(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	valid := func(cd, ad []byte) []byte { return sha256Sum(slices.Concat(ad, sha256Sum(cd))) }
	for _, tc := range []struct {
		name    string
		nonce   func(cd, ad []byte) []byte
		certKey crypto.PublicKey
		ok      bool
	}{
		{"valid", valid, nil, true},
		{"nonce of other data", func(cd, _ []byte) []byte { return sha256Sum(cd) }, nil, false},
		{"no nonce", nil, nil, false},
		{"certificate for another key", valid, &other.PublicKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp := newTestRP(t, Config{}, newMemStore())
			a := newSoftAuthenticator(t)
			reg, err := registerAttested(t, rp, a, "apple", appleStatement(t, ca, a, tc.nonce, tc.certKey))
			if !tc.ok {
				if !errors.Is(err, ErrAttestation) {
					t.Fatalf("FinishRegistration = %v, want ErrAttestation", err)
				}
				return
			}
			if err != nil || reg.Credential.AttestationType != AttestationAnonCA {
				t.Fatalf("FinishRegistration = %+v, %v", reg.Credential, err)
			}
		})
	}
}

func TestAttestationRootsForNewFormats(t *testing.T) {
	ca, otherCA := newTestCA(t), newTestCA(t)
	for _, format := range []string{"tpm", "android-key", "apple"} {
		build := func(a *softAuthenticator) func(cd, ad []byte) cborPairs {
			switch format {
			case "tpm":
				return tpmStatement(t, ca, a, nil)
			case "android-key":
				return androidKeyStatement(t, ca, a, nil)
			}
			return appleStatement(t, ca, a, func(cd, ad []byte) []byte { return sha256Sum(slices.Concat(ad, sha256Sum(cd))) }, nil)
		}
		for _, tc := range []struct {
			roots   *x509.CertPool
			trusted bool
		}{{ca.pool(), true}, {otherCA.pool(), false}} {
			rp := newTestRP(t, Config{Attestation: ConveyanceDirect, AttestationRoots: tc.roots}, newMemStore())
			a := newSoftAuthenticator(t)
			_, err := registerAttested(t, rp, a, format, build(a))
			if (err == nil) != tc.trusted || err != nil && !errors.Is(err, ErrAttestation) {
				t.Errorf("%s, trusted root %v: FinishRegistration = %v", format, tc.trusted, err)
			}
		}
	}
}

func FuzzTPMStructures(f *testing.F) {
	a := newSoftAuthenticator(f)
	f.Add(tpmECCPublic(&a.key.PublicKey))
	f.Add(tpmCertInfo(tpmGeneratedValue, tpmSTAttestCertify, make([]byte, 32), make([]byte, 34)))
	f.Fuzz(func(t *testing.T, data []byte) {
		parseTPMPublic(data)
		parseTPMCertifyInfo(data)
	})
}

func FuzzAttestationExtensions(f *testing.F) {
	f.Add(keyDescriptionDER(make([]byte, 32), akList(akAllApplications()), akList(akPurpose(kmPurposeSign), akOrigin(kmOriginGenerated))))
	f.Add(tpmSAN(tpmDeviceAttributes...))
	f.Add(appleNonceDER(make([]byte, 32)))
	f.Fuzz(func(t *testing.T, data []byte) {
		parseKeyDescription(data)
		hasTPMDeviceAttributes(data)
		appleNonce(data)
	})
}
