package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"math/big"
	"os"
	"testing"
)

// RFC 7515 Appendix A.2: an RSA private key with an RS256 signature over
// the signing input below. RSASSA-PKCS1-v1_5 is deterministic, so the
// signature must match exactly.
const (
	rfc7515RSAKey = `{"kty":"RSA",` +
		`"n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",` +
		`"e":"AQAB",` +
		`"d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",` +
		`"p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",` +
		`"q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",` +
		`"dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",` +
		`"dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",` +
		`"qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"}`
	rfc7515RS256Input = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	rfc7515RS256Sig   = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
		"AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
		"BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
		"0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
		"hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
		"p0igcN_IoypGlUPQGe77Rw"
)

// RFC 7517 Appendix A.2, with "use":"enc" removed (it is tested below).
const rfc7517ECKey = `{"kty":"EC","crv":"P-256",` +
	`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
	`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
	`"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","kid":"1"}`

// RFC 8037 Appendix A.1, used for the signature in Appendix A.4.
const rfc8037Ed25519Key = `{"kty":"OKP","crv":"Ed25519",` +
	`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
	`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

func mustParsePrivate(t *testing.T, s string) PrivateJWK {
	t.Helper()
	k, err := ParsePrivateJWK([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParsePrivateJWKSignatureVectors(t *testing.T) {
	for name, tc := range map[string]struct {
		jwk        string
		alg        Algorithm
		input, sig string
	}{
		"RFC 7515 A.2 RS256": {rfc7515RSAKey, RS256, rfc7515RS256Input, rfc7515RS256Sig},
		"RFC 8037 A.4 Ed25519": {rfc8037Ed25519Key, EdDSA,
			"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc",
			"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"},
	} {
		t.Run(name, func(t *testing.T) {
			k := mustParsePrivate(t, tc.jwk)
			if _, err := NewSigner(tc.alg, k.Key); err != nil {
				t.Fatalf("NewSigner rejected the parsed key: %v", err)
			}
			sig, err := sign(tc.alg, k.Key, []byte(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			if got := b64.EncodeToString(sig); got != tc.sig {
				t.Fatalf("signature = %s, want %s", got, tc.sig)
			}
		})
	}
}

func TestParsePrivateJWKRFC7517EC(t *testing.T) {
	k := mustParsePrivate(t, rfc7517ECKey)
	if k.KeyID != "1" {
		t.Fatalf("kid = %q", k.KeyID)
	}
	s, err := NewSigner(ES256, k.Key, WithKeyID(k.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Sign(validClaims())
	if err != nil {
		t.Fatal(err)
	}
	pub := mustParseJWK(t, withoutMembers(t, rfc7517ECKey, "d"))
	if _, err := newVerifier(t, NewStaticKeySet(pub)).Verify(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
}

func TestParsePrivateJWKKeepsAlgorithm(t *testing.T) {
	k := mustParsePrivate(t, withMembers(t, rfc7515RSAKey, map[string]any{"alg": "PS256", "kid": "r1", "use": "sig", "key_ops": []string{"sign"}}))
	if k.Algorithm != PS256 || k.KeyID != "r1" {
		t.Fatalf("got alg %q kid %q", k.Algorithm, k.KeyID)
	}
}

func TestParsePrivateJWKRoundTripsGeneratedKeys(t *testing.T) {
	loadKeys(t)
	enc := func(n *big.Int) string { return b64.EncodeToString(n.Bytes()) }
	ecJWK := func(k *ecdsa.PrivateKey) string {
		pub, _ := json.Marshal(JWK{Key: &k.PublicKey})
		d, _ := k.Bytes()
		return withMembers(t, string(pub), map[string]any{"d": b64.EncodeToString(d)})
	}
	rsaPub, _ := json.Marshal(JWK{Key: &rsaKey.PublicKey})
	edPub, _ := json.Marshal(JWK{Key: edKey.Public()})
	for name, tc := range map[string]struct {
		jwk  string
		want crypto.Signer
	}{
		"RSA": {withMembers(t, string(rsaPub), map[string]any{
			"d": enc(rsaKey.D), "p": enc(rsaKey.Primes[0]), "q": enc(rsaKey.Primes[1]),
			"dp": enc(rsaKey.Precomputed.Dp), "dq": enc(rsaKey.Precomputed.Dq), "qi": enc(rsaKey.Precomputed.Qinv),
		}), rsaKey},
		"P-256":   {ecJWK(p256Key), p256Key},
		"P-384":   {ecJWK(p384Key), p384Key},
		"P-521":   {ecJWK(p521Key), p521Key},
		"Ed25519": {withMembers(t, string(edPub), map[string]any{"d": b64.EncodeToString(edKey.Seed())}), edKey},
	} {
		t.Run(name, func(t *testing.T) {
			k := mustParsePrivate(t, tc.jwk)
			if !k.Key.(interface{ Equal(crypto.PrivateKey) bool }).Equal(tc.want) {
				t.Fatal("parsed key differs from the original")
			}
		})
	}
}

func TestParsePrivateJWKRejections(t *testing.T) {
	n := elliptic.P256().Params().N
	order := b64.EncodeToString(n.FillBytes(make([]byte, 32)))
	zero := b64.EncodeToString(make([]byte, 32))
	otherSeed := b64.EncodeToString(make([]byte, ed25519.SeedSize))
	bad := map[string]string{
		"public only":         withoutMembers(t, rfc7517ECKey, "d"),
		"symmetric":           `{"kty":"oct","k":"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"}`,
		"use enc":             withMembers(t, rfc7517ECKey, map[string]any{"use": "enc"}),
		"key_ops verify":      withMembers(t, rfc7517ECKey, map[string]any{"key_ops": []string{"verify"}}),
		"alg for other curve": withMembers(t, rfc7517ECKey, map[string]any{"alg": "ES384"}),
		"HMAC alg":            withMembers(t, rfc7515RSAKey, map[string]any{"alg": "HS256"}),
		"RSA without CRT":     withoutMembers(t, rfc7515RSAKey, "p", "q", "dp", "dq", "qi"),
		"RSA missing qi":      withoutMembers(t, rfc7515RSAKey, "qi"),
		"RSA wrong qi":        withMembers(t, rfc7515RSAKey, map[string]any{"qi": member(t, rfc7515RSAKey, "dp")}),
		"RSA swapped dp, dq": withMembers(t, rfc7515RSAKey, map[string]any{
			"dp": member(t, rfc7515RSAKey, "dq"), "dq": member(t, rfc7515RSAKey, "dp")}),
		"RSA wrong d":        withMembers(t, rfc7515RSAKey, map[string]any{"d": "AQAB"}),
		"RSA wrong p":        withMembers(t, rfc7515RSAKey, map[string]any{"p": member(t, rfc7515RSAKey, "q")}),
		"RSA multi-prime":    withMembers(t, rfc7515RSAKey, map[string]any{"oth": []any{map[string]any{"r": "AQAB", "d": "AQAB", "t": "AQAB"}}}),
		"RSA d not a string": withMembers(t, rfc7515RSAKey, map[string]any{"d": 1}),
		"EC d of another key": withMembers(t, rfc7517ECKey, map[string]any{
			"d": member(t, rfc7517ECKey, "y")}),
		"EC d zero":         withMembers(t, rfc7517ECKey, map[string]any{"d": zero}),
		"EC d equal to n":   withMembers(t, rfc7517ECKey, map[string]any{"d": order}),
		"EC d short":        withMembers(t, rfc7517ECKey, map[string]any{"d": b64.EncodeToString(make([]byte, 31))}),
		"EC d padded":       withMembers(t, rfc7517ECKey, map[string]any{"d": member(t, rfc7517ECKey, "d") + "="}),
		"EC with p":         withMembers(t, rfc7517ECKey, map[string]any{"p": "AQAB"}),
		"OKP d of another":  withMembers(t, rfc8037Ed25519Key, map[string]any{"d": otherSeed}),
		"OKP d short":       withMembers(t, rfc8037Ed25519Key, map[string]any{"d": "AQAB"}),
		"OKP invalid x":     withMembers(t, rfc8037Ed25519Key, map[string]any{"x": "AQAB"}),
		"duplicate members": `{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
	}
	for name, in := range bad {
		if _, err := ParsePrivateJWK([]byte(in)); err == nil {
			t.Errorf("%s: ParsePrivateJWK succeeded", name)
		}
	}
}

func TestPublicParsersRejectPrivateMembers(t *testing.T) {
	public := withoutMembers(t, rfc8037Ed25519Key, "d")
	inputs := map[string]string{
		"RSA private key": rfc7515RSAKey,
		"EC private key":  rfc7517ECKey,
		"OKP private key": rfc8037Ed25519Key,
	}
	for _, m := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		inputs["public key with "+m] = withMembers(t, public, map[string]any{m: "AQAB"})
	}
	inputs["public key with oth"] = withMembers(t, public, map[string]any{"oth": []any{}})
	inputs["public key with null d"] = withMembers(t, public, map[string]any{"d": nil})
	for name, in := range inputs {
		if _, err := ParseJWK([]byte(in)); err == nil {
			t.Errorf("%s: ParseJWK succeeded", name)
		}
		set, err := ParseJWKSet([]byte(`{"keys":[` + in + `,` + withMembers(t, public, map[string]any{"kid": "pub"}) + `]}`))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(set.Keys) != 1 || set.Keys[0].KeyID != "pub" {
			t.Errorf("%s: ParseJWKSet kept %+v", name, set.Keys)
		}
	}
}

func FuzzParseJWK(f *testing.F) {
	for _, s := range []string{rfc7515RSAKey, rfc7517ECKey, rfc8037Ed25519Key, `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`} {
		f.Add([]byte(s))
	}
	var x5c struct {
		JWK jsontext.Value `json:"jwk"`
	}
	if data, err := os.ReadFile("testdata/openssl_x5c.json"); err == nil && json.Unmarshal(data, &x5c) == nil {
		f.Add([]byte(x5c.JWK))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pub, pubErr := ParseJWK(data)
		priv, privErr := ParsePrivateJWK(data)
		if pubErr == nil && privErr == nil {
			t.Fatalf("%s parsed as both a public and a private key", data)
		}
		if pubErr == nil {
			if _, err := json.Marshal(pub); err != nil {
				t.Fatalf("parsed public key does not marshal: %v", err)
			}
		}
		if privErr == nil {
			if _, err := publicKeyOf(priv.Key); err != nil {
				t.Fatalf("parsed private key is unusable: %v", err)
			}
		}
	})
}

func mustParseJWK(t *testing.T, s string) JWK {
	t.Helper()
	k, err := ParseJWK([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwkMembers(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func member(t *testing.T, s, name string) string {
	t.Helper()
	return jwkMembers(t, s)[name].(string)
}

func withMembers(t *testing.T, s string, set map[string]any) string {
	t.Helper()
	m := jwkMembers(t, s)
	maps.Copy(m, set)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func withoutMembers(t *testing.T, s string, names ...string) string {
	t.Helper()
	m := jwkMembers(t, s)
	for _, n := range names {
		delete(m, n)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
