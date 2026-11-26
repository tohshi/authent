package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

// RFC 8949 Appendix A examples within the supported subset.
func TestCBORDecodeRFC8949Examples(t *testing.T) {
	for _, tc := range []struct {
		hex  string
		want any
	}{
		{"00", int64(0)},
		{"17", int64(23)},
		{"1818", int64(24)},
		{"1903e8", int64(1000)},
		{"1a000f4240", int64(1000000)},
		{"1b000000e8d4a51000", int64(1000000000000)},
		{"20", int64(-1)},
		{"3863", int64(-100)},
		{"3903e7", int64(-1000)},
		{"f4", false},
		{"f5", true},
		{"f6", nil},
		{"40", []byte{}},
		{"4401020304", []byte{1, 2, 3, 4}},
		{"60", ""},
		{"6449455446", "IETF"},
		{"62c3bc", "ü"},
		{"80", []any{}},
		{"83010203", []any{int64(1), int64(2), int64(3)}},
		{"8301820203820405", []any{int64(1), []any{int64(2), int64(3)}, []any{int64(4), int64(5)}}},
		{"a0", cborMap{}},
		{"a201020304", cborMap{int64(1): int64(2), int64(3): int64(4)}},
		{"a26161016162820203", cborMap{"a": int64(1), "b": []any{int64(2), int64(3)}}},
	} {
		got, err := cborDecodeAll(mustHex(t, tc.hex))
		if err != nil {
			t.Errorf("%s: %v", tc.hex, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s = %#v, want %#v", tc.hex, got, tc.want)
		}
	}
}

func TestCBORRejects(t *testing.T) {
	deep := bytes.Repeat([]byte{0x81}, cborMaxDepth+2)
	deep = append(deep, 0)
	for name, h := range map[string]string{
		"empty":                "",
		"uint64 overflow":      "1bffffffffffffffff",
		"negative overflow":    "3bffffffffffffffff",
		"truncated argument":   "19",
		"truncated byte str":   "4401",
		"huge byte str length": "5bffffffffffffffff",
		"indefinite byte str":  "5f4101ff",
		"indefinite array":     "9f01ff",
		"indefinite map":       "bf0102ff",
		"reserved info":        "1c",
		"tag":                  "c11a514b67b0",
		"float":                "f93c00",
		"undefined":            "f7",
		"simple value":         "f0",
		"invalid UTF-8":        "62c328",
		"duplicate key":        "a2010201 03",
		"byte string key":      "a1410102",
		"array key":            "a1800102",
		"huge array":           "9bffffffffffffffff",
		"huge map":             "bbffffffffffffffff",
		"many items":           "9a00010000",
		"trailing":             "0000",
		"deep":                 hex.EncodeToString(deep),
	} {
		if _, err := cborDecodeAll(mustHex(t, h)); !errors.Is(err, errCBOR) {
			t.Errorf("%s: err = %v, want errCBOR", name, err)
		}
	}
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(string(bytes.ReplaceAll([]byte(s), []byte(" "), nil)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseCOSEKey(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pt, _ := ec.PublicKey.Bytes()
	x, y := pt[1:33], pt[33:]
	if alg, pub, err := parseCOSEKey(cborEnc(cborPairs{{1, 2}, {3, -7}, {-1, 1}, {-2, x}, {-3, y}})); err != nil || alg != ES256 || !ec.PublicKey.Equal(pub) {
		t.Fatalf("parseCOSEKey(ES256) = %v, %v, %v", alg, pub, err)
	}

	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	offCurve := bytes.Clone(y)
	offCurve[0] ^= 1
	for name, key := range map[string]cborPairs{
		"no alg":            {{1, 2}, {-1, 1}, {-2, x}, {-3, y}},
		"no kty":            {{3, -7}, {-1, 1}, {-2, x}, {-3, y}},
		"curve mismatch":    {{1, 2}, {3, -7}, {-1, 2}, {-2, x}, {-3, y}},
		"alg mismatch":      {{1, 2}, {3, -35}, {-1, 1}, {-2, x}, {-3, y}},
		"kty mismatch":      {{1, 3}, {3, -7}, {-1, x}, {-2, []byte{1, 0, 1}}},
		"off curve":         {{1, 2}, {3, -7}, {-1, 1}, {-2, x}, {-3, offCurve}},
		"compressed point":  {{1, 2}, {3, -7}, {-1, 1}, {-2, x}, {-3, true}},
		"short coordinate":  {{1, 2}, {3, -7}, {-1, 1}, {-2, x[1:]}, {-3, y}},
		"private EC key":    {{1, 2}, {3, -7}, {-1, 1}, {-2, x}, {-3, y}, {-4, x}},
		"Ed448":             {{1, 1}, {3, -8}, {-1, 7}, {-2, make([]byte, 57)}},
		"private OKP key":   {{1, 1}, {3, -8}, {-1, 6}, {-2, make([]byte, 32)}, {-4, make([]byte, 32)}},
		"short RSA":         {{1, 3}, {3, -257}, {-1, small.N.Bytes()}, {-2, []byte{1, 0, 1}}},
		"even RSA exponent": {{1, 3}, {3, -257}, {-1, make([]byte, 256)}, {-2, []byte{2}}},
		"private RSA key":   {{1, 3}, {3, -257}, {-1, make([]byte, 256)}, {-2, []byte{1, 0, 1}}, {-3, []byte{1}}},
		"unknown kty":       {{1, 4}, {3, -7}},
	} {
		if _, _, err := parseCOSEKey(cborEnc(key)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := parseCOSEKey(cborEnc([]any{1})); err == nil {
		t.Error("non-map COSE key accepted")
	}
}

func TestVerifySignatureBindsKeyType(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	msg := []byte("msg")
	h := sha256Sum(msg)
	sig, _ := ecdsa.SignASN1(rand.Reader, ec, h)
	// A P-384 key must not verify as ES256, even with a SHA-256 signature.
	if err := verifySignature(ES256, &ec.PublicKey, msg, sig); err == nil {
		t.Fatal("P-384 key accepted for ES256")
	}
	if err := verifySignature(RS256, &ec.PublicKey, msg, sig); err == nil {
		t.Fatal("EC key accepted for RS256")
	}
}

func TestParseAuthData(t *testing.T) {
	a := newSoftAuthenticator(t)
	raw := a.authData(true)
	ad, err := parseAuthData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ad.credentialID, a.credID) || !bytes.Equal(ad.publicKey, a.coseKey()) || ad.signCount != 0 {
		t.Fatalf("unexpected %+v", ad)
	}

	// Extensions after the credential public key.
	a.flags |= flagED
	a.trailing = cborEnc(cborPairs{{"credProtect", 2}})
	if ad, err := parseAuthData(a.authData(true)); err != nil || ad.extensions["credProtect"] != int64(2) {
		t.Fatalf("with extensions = %+v, %v", ad, err)
	}

	for name, b := range map[string][]byte{
		"short":                   raw[:36],
		"truncated credential ID": raw[:37+18+3],
		"zero-length ID":          append(bytes.Clone(raw[:37+16]), 0, 0),
		"truncated public key":    raw[:len(raw)-1],
		"ED without extensions":   append(bytes.Clone(raw[:32]), raw[32]|flagED, 0, 0, 0, 0),
		"extensions not a map":    append(append(bytes.Clone(raw[:32]), flagUP|flagED, 0, 0, 0, 0), 0x01),
		"trailing":                append(bytes.Clone(raw), 0),
		"extension key not text":  append(append(bytes.Clone(raw[:32]), flagUP|flagED, 0, 0, 0, 0), cborEnc(cborPairs{{1, 2}})...),
	} {
		if _, err := parseAuthData(b); !errors.Is(err, errAuthData) {
			t.Errorf("%s: err = %v, want errAuthData", name, err)
		}
	}
}

func FuzzCBOR(f *testing.F) {
	f.Add(mustHex(f, "a26161016162820203"))
	f.Add(newSoftAuthenticator(f).coseKey())
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := cborDecodeAll(data)
		if err == nil {
			if m, ok := v.(cborMap); ok {
				coseKeyFromMap(m)
			}
		}
	})
}

func FuzzParseAuthData(f *testing.F) {
	a := newSoftAuthenticator(f)
	f.Add(a.authData(true))
	f.Add(a.authData(false))
	f.Fuzz(func(t *testing.T, data []byte) {
		ad, err := parseAuthData(data)
		if err != nil {
			return
		}
		if ad.has(flagAT) {
			parseCOSEKey(ad.publicKey)
		}
	})
}
