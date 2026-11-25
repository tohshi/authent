package jwt

import (
	"context"
	"crypto"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/tohshi/authent"
)

func TestThumbprintVectors(t *testing.T) {
	for name, tc := range map[string]struct{ jwk, want string }{
		// RFC 7638 §3.1. Members other than kty, n and e are ignored.
		"RFC 7638 RSA": {
			`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`,
			"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		},
		// RFC 8037 Appendix A.3.
		"RFC 8037 Ed25519": {
			`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
			"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
		},
		// RFC 9449 §6.1: the jkt of the key in the example DPoP proofs.
		"RFC 9449 EC": {
			`{"kty":"EC","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","crv":"P-256"}`,
			"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
		},
	} {
		t.Run(name, func(t *testing.T) {
			k, err := ParseJWK([]byte(tc.jwk))
			if err != nil {
				t.Fatal(err)
			}
			sum, err := k.Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			if got := b64.EncodeToString(sum); got != tc.want {
				t.Fatalf("thumbprint = %s, want %s", got, tc.want)
			}
		})
	}
	hmac, _ := NewHMACKey("", HS256, hmacKey)
	if _, err := hmac.Thumbprint(crypto.SHA256); err == nil {
		t.Fatal("HMAC key has a thumbprint")
	}
}

// RFC 9449 Figure 13: a DPoP proof made by an independent implementation.
const rfc9449Proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik" +
	"VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR" +
	"nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE" +
	"QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj" +
	"oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z" +
	"WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF" +
	"c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E" +
	"OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"

func TestVerifyWithEmbeddedKeyRFC9449Vector(t *testing.T) {
	got, err := VerifyWithEmbeddedKey(rfc9449Proof, ES256, RS256)
	if err != nil {
		t.Fatalf("VerifyWithEmbeddedKey = %v", err)
	}
	if got.Header.Algorithm != ES256 || got.Header.Type != "dpop+jwt" {
		t.Fatalf("header = %+v", got.Header)
	}
	var claims map[string]any
	if err := json.Unmarshal(got.Payload, &claims); err != nil || claims["htm"] != "GET" {
		t.Fatalf("payload = %s (%v)", got.Payload, err)
	}
	sum, _ := got.Key.Thumbprint(crypto.SHA256)
	if b64.EncodeToString(sum) != "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" {
		t.Fatal("unexpected key")
	}
	if _, err := VerifyWithEmbeddedKey(rfc9449Proof, RS256); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("alg not allowed: err = %v", err)
	}
}

func TestVerifyWithEmbeddedKeyRoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{RS256, PS256, ES256, ES384, ES512, EdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			s, err := NewSigner(alg, signingKeyFor(t, alg), WithJWKHeader(), WithType("dpop+jwt"))
			if err != nil {
				t.Fatal(err)
			}
			tok, err := s.SignPayload([]byte(`{"jti":"x"}`))
			if err != nil {
				t.Fatal(err)
			}
			got, err := VerifyWithEmbeddedKey(tok, alg)
			if err != nil {
				t.Fatalf("VerifyWithEmbeddedKey = %v", err)
			}
			want, _ := s.VerificationKey().Thumbprint(crypto.SHA256)
			if sum, _ := got.Key.Thumbprint(crypto.SHA256); string(sum) != string(want) {
				t.Fatal("embedded key differs from the signing key")
			}
			// The ordinary Verifier never uses the embedded key.
			v := newVerifier(t, NewStaticKeySet(), WithAlgorithms(alg))
			if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrNoMatchingKey) {
				t.Fatalf("Verifier used the jwk header: err = %v", err)
			}
		})
	}
	if _, err := NewSigner(HS256, hmacKey, WithJWKHeader()); err == nil {
		t.Fatal("HMAC secret embedded in a header")
	}
}

func TestVerifyWithEmbeddedKeyRejections(t *testing.T) {
	loadKeys(t)
	pub := func(k JWK) map[string]any {
		b, _ := json.Marshal(k)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	ecJWK := pub(JWK{Key: &p256Key.PublicKey})
	withPrivate := pub(JWK{Key: &p256Key.PublicKey})
	withPrivate["d"] = b64.EncodeToString(p256Key.D.Bytes())
	pinnedJWK := pub(JWK{Key: &p256Key.PublicKey, Algorithm: ES256})
	otherJWK := pub(JWK{Key: &p384Key.PublicKey})
	es := func(h map[string]any) string { return forge(t, ES256, p256Key, h, `{"jti":"x"}`) }
	good := es(map[string]any{"alg": "ES256", "jwk": ecJWK})
	parts := strings.Split(good, ".")

	for name, tc := range map[string]struct {
		token string
		want  error
	}{
		"missing jwk":       {es(map[string]any{"alg": "ES256"}), ErrMalformed},
		"jwk not an object": {es(map[string]any{"alg": "ES256", "jwk": "key"}), ErrMalformed},
		"private key":       {es(map[string]any{"alg": "ES256", "jwk": withPrivate}), ErrMalformed},
		"key of another curve": {
			es(map[string]any{"alg": "ES256", "jwk": otherJWK}), ErrNoMatchingKey,
		},
		"jwk pinned to another alg": {
			forge(t, ES256, p256Key, map[string]any{"alg": "ES384", "jwk": pinnedJWK}, `{}`), ErrNoMatchingKey,
		},
		"alg none":         {encodeSegments(t, map[string]any{"alg": "none", "jwk": ecJWK}, `{}`) + ".c2ln", ErrUnsupportedAlgorithm},
		"tampered payload": {parts[0] + "." + b64.EncodeToString([]byte(`{"jti":"y"}`)) + "." + parts[2], ErrInvalidSignature},
		"crit header":      {es(map[string]any{"alg": "ES256", "jwk": ecJWK, "crit": []string{"x"}}), ErrUnsupportedHeader},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyWithEmbeddedKey(tc.token, ES256, ES384)
			if !errors.Is(err, tc.want) || !errors.Is(err, authent.ErrUnauthenticated) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := VerifyWithEmbeddedKey(good, HS256, ES256); err == nil {
		t.Fatal("symmetric algorithm accepted")
	}
	if _, err := VerifyWithEmbeddedKey(good); err == nil {
		t.Fatal("empty algorithm list accepted")
	}
}

func TestConfirmationClaim(t *testing.T) {
	ctx := context.Background()
	for name, cnf := range map[string]any{
		"jkt":  map[string]any{"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"},
		"x5t":  map[string]any{"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"},
		"null": nil,
	} {
		t.Run(name, func(t *testing.T) {
			c := validClaims()
			c.Extra["cnf"] = cnf
			tok, s := mustSign(t, ES256, c)
			ks := NewStaticKeySet(s.VerificationKey())
			if _, err := newVerifier(t, ks).Verify(ctx, tok); !errors.Is(err, ErrSenderConstrained) {
				t.Fatalf("bound token accepted as bearer: err = %v", err)
			}
			if _, err := newVerifier(t, ks, WithConfirmationClaim()).Verify(ctx, tok); err != nil {
				t.Fatalf("WithConfirmationClaim: err = %v", err)
			}
		})
	}
}
