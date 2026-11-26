package totp

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

var testSecret = b32.EncodeToString([]byte("12345678901234567890"))

func TestParseURI(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := map[string]ProvisioningURI{
		// The example from the Key URI format documentation, with a
		// 160-bit secret.
		"otpauth://totp/Example:alice@google.com?secret=" + testSecret + "&issuer=Example": {
			Type: TypeTOTP, Issuer: "Example", Account: "alice@google.com",
			Key: Key{Secret: secret, Algorithm: SHA1, Digits: 6, Period: 30 * time.Second},
		},
		"otpauth://totp/ACME%20Co:%20%20john?secret=" + testSecret + "&algorithm=SHA512&digits=8&period=60": {
			Type: TypeTOTP, Issuer: "ACME Co", Account: "john",
			Key: Key{Secret: secret, Algorithm: SHA512, Digits: 8, Period: time.Minute},
		},
		"otpauth://totp/bob?issuer=ACME+Co&secret=" + testSecret: {
			Type: TypeTOTP, Issuer: "ACME Co", Account: "bob",
			Key: Key{Secret: secret, Algorithm: SHA1, Digits: 6, Period: 30 * time.Second},
		},
		"otpauth://hotp/ACME:carol?secret=" + testSecret + "&counter=18446744073709551615": {
			Type: TypeHOTP, Issuer: "ACME", Account: "carol", Counter: 1<<64 - 1,
			Key: Key{Secret: secret, Algorithm: SHA1, Digits: 6},
		},
	}
	for in, want := range cases {
		got, err := ParseURI(in)
		if err != nil {
			t.Errorf("ParseURI(%q) = %v", in, err)
			continue
		}
		if !equalURI(got, want) {
			t.Errorf("ParseURI(%q) =\n%+v\nwant\n%+v", in, got, want)
		}
	}
}

func TestParseURIRoundTrip(t *testing.T) {
	k, _ := GenerateKey(WithAlgorithm(SHA256), WithDigits(7), WithPeriod(45*time.Second))
	hk := k
	hk.Period = 0
	for _, p := range []ProvisioningURI{
		{Type: TypeTOTP, Key: k, Issuer: "ACME & Sons/100%", Account: "a b+c@example.com"},
		{Type: TypeTOTP, Key: k, Account: "solo"},
		{Type: TypeHOTP, Key: hk, Issuer: "ACME", Account: "dave", Counter: 42},
	} {
		s, err := p.URI()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseURI(s)
		if err != nil || !equalURI(got, p) {
			t.Errorf("ParseURI(%q) = %+v, %v, want %+v", s, got, err, p)
		}
	}
}

func TestParseURIRejects(t *testing.T) {
	ok := "otpauth://totp/ACME:john?secret=" + testSecret
	if _, err := ParseURI(ok); err != nil {
		t.Fatalf("baseline URI rejected: %v", err)
	}
	for name, in := range map[string]string{
		"other scheme":            "http://totp/ACME:john?secret=" + testSecret,
		"upper-case scheme":       "OTPAUTH://totp/ACME:john?secret=" + testSecret,
		"upper-case type":         "otpauth://TOTP/ACME:john?secret=" + testSecret,
		"unknown type":            "otpauth://motp/ACME:john?secret=" + testSecret,
		"no parameters":           "otpauth://totp/ACME:john",
		"fragment":                ok + "#x",
		"no secret":               "otpauth://totp/ACME:john?issuer=ACME",
		"empty account":           "otpauth://totp/ACME:?secret=" + testSecret,
		"empty issuer":            "otpauth://totp/:john?secret=" + testSecret,
		"no label":                "otpauth://totp/?secret=" + testSecret,
		"account of spaces":       "otpauth://totp/%20?secret=" + testSecret + "&issuer=ACME",
		"two colons":              "otpauth://totp/A:B:john?secret=" + testSecret,
		"encoded second colon":    "otpauth://totp/A:B%3Ajohn?secret=" + testSecret,
		"slash in label":          "otpauth://totp/A/john?secret=" + testSecret,
		"bad label escape":        "otpauth://totp/A%zzjohn?secret=" + testSecret,
		"issuer mismatch":         ok + "&issuer=Evil",
		"colon in issuer param":   "otpauth://totp/john?secret=" + testSecret + "&issuer=a:b",
		"repeated secret":         ok + "&secret=" + testSecret,
		"unknown parameter":       ok + "&image=x",
		"empty parameter":         ok + "&digits=",
		"empty segment":           ok + "&&digits=6",
		"no equals sign":          ok + "&digits",
		"lower-case secret":       "otpauth://totp/ACME:john?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
		"padded secret":           "otpauth://totp/ACME:john?secret=" + testSecret[:26] + "======",
		"non-canonical secret":    "otpauth://totp/ACME:john?secret=GEZDGNBVGY3TQOJQGEZDGNBVGZ",
		"secret with newline":     "otpauth://totp/ACME:john?secret=" + testSecret[:8] + "%0A" + testSecret[8:],
		"short secret":            "otpauth://totp/ACME:john?secret=GEZDGNBVGY3TQOJQ",
		"lower-case algorithm":    ok + "&algorithm=sha1",
		"unknown algorithm":       ok + "&algorithm=MD5",
		"five digits":             ok + "&digits=5",
		"nine digits":             ok + "&digits=9",
		"leading zero":            ok + "&digits=06",
		"plus sign":               ok + "&digits=%2B6",
		"zero period":             ok + "&period=0",
		"huge period":             ok + "&period=99999999999999999999",
		"overflowing period":      ok + "&period=9223372037",
		"counter in TOTP":         ok + "&counter=1",
		"period in HOTP":          "otpauth://hotp/ACME:john?secret=" + testSecret + "&counter=1&period=30",
		"HOTP without counter":    "otpauth://hotp/ACME:john?secret=" + testSecret,
		"negative counter":        "otpauth://hotp/ACME:john?secret=" + testSecret + "&counter=-1",
		"counter past uint64":     "otpauth://hotp/ACME:john?secret=" + testSecret + "&counter=18446744073709551616",
		"semicolon separator":     "otpauth://totp/ACME:john?secret=" + testSecret + ";digits=6",
		"bad query escape":        ok + "&issuer=%zz",
		"userinfo-like authority": "otpauth://user@totp/ACME:john?secret=" + testSecret,
	} {
		if _, err := ParseURI(in); !errors.Is(err, ErrInvalidURI) {
			t.Errorf("%s: ParseURI(%q) = %v, want ErrInvalidURI", name, in, err)
		}
	}
}

func equalURI(a, b ProvisioningURI) bool {
	return a.Type == b.Type && a.Issuer == b.Issuer && a.Account == b.Account && a.Counter == b.Counter &&
		bytes.Equal(a.Key.Secret, b.Key.Secret) && a.Key.Algorithm == b.Key.Algorithm &&
		a.Key.Digits == b.Key.Digits && a.Key.Period == b.Key.Period
}

func FuzzParseURI(f *testing.F) {
	f.Add("otpauth://totp/Example:alice@google.com?secret=" + testSecret + "&issuer=Example")
	f.Add("otpauth://totp/ACME%20Co:%20john?secret=" + testSecret + "&algorithm=SHA512&digits=8&period=60")
	f.Add("otpauth://hotp/ACME:carol?secret=" + testSecret + "&counter=7")
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseURI(s)
		if err != nil {
			return
		}
		u, err := p.URI()
		if err != nil {
			t.Fatalf("parsed %q but cannot format %+v: %v", s, p, err)
		}
		again, err := ParseURI(u)
		if err != nil || !equalURI(again, p) {
			t.Fatalf("%q parsed to %+v, which formats as %q and parses to %+v, %v", s, p, u, again, err)
		}
	})
}
