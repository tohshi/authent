package webauthn

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"reflect"
	"testing"

	"github.com/tohshi/authent"
)

func TestConditionalCreate(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	rp := newTestRP(t, Config{}, store)

	a := newSoftAuthenticator(t)
	a.flags &^= flagUP
	_, ch, err := rp.BeginRegistration(testUser, nil, WithConditionalCreate())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(ch)
	var back Challenge
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	reg, err := rp.FinishRegistration(ctx, back, a.create(ch))
	if err != nil {
		t.Fatalf("conditional FinishRegistration without UP = %v", err)
	}

	b := newSoftAuthenticator(t)
	b.flags &^= flagUP
	_, ch, _ = rp.BeginRegistration(testUser, nil)
	if _, err := rp.FinishRegistration(ctx, ch, b.create(ch)); !errors.Is(err, ErrUserNotPresent) {
		t.Fatalf("modal FinishRegistration without UP = %v, want ErrUserNotPresent", err)
	}

	uv := newTestRP(t, Config{UserVerification: UserVerificationRequired}, newMemStore())
	c := newSoftAuthenticator(t)
	c.flags = 0
	_, ch, _ = uv.BeginRegistration(testUser, nil, WithConditionalCreate())
	if _, err := uv.FinishRegistration(ctx, ch, c.create(ch)); !errors.Is(err, ErrUserNotVerified) {
		t.Fatalf("conditional FinishRegistration without UV = %v, want ErrUserNotVerified", err)
	}

	if _, _, err := rp.BeginLogin([]Credential{reg.Credential}, WithConditionalCreate()); err == nil {
		t.Fatal("BeginLogin accepted WithConditionalCreate")
	}
	if _, _, err := rp.BeginDiscoverableLogin(WithConditionalCreate()); err == nil {
		t.Fatal("BeginDiscoverableLogin accepted WithConditionalCreate")
	}
}

func TestExtensionInputsJSON(t *testing.T) {
	rp := newTestRP(t, Config{}, newMemStore())
	opts, _, err := rp.BeginRegistration(testUser, nil, WithExtensions(ExtensionInputs{
		CredProps: true,
		PRF:       &PRFInputs{Eval: &PRFValues{First: []byte("salt-1")}},
		LargeBlob: &LargeBlobInputs{Support: LargeBlobRequired},
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"credProps": true,
		"prf":       map[string]any{"eval": map[string]any{"first": b64.EncodeToString([]byte("salt-1"))}},
		"largeBlob": map[string]any{"support": "required"},
	}
	if got := extensionsJSON(t, opts); !jsonEqual(got, want) {
		t.Fatalf("registration extensions = %v", got)
	}

	cred := Credential{ID: []byte("cred-1"), Subject: "u-1", UserHandle: []byte("h")}
	ropts, _, err := rp.BeginLogin([]Credential{cred}, WithExtensions(ExtensionInputs{
		AppID: "https://example.org",
		PRF: &PRFInputs{EvalByCredential: map[string]PRFValues{
			b64.EncodeToString(cred.ID): {First: []byte("a"), Second: []byte("b")},
		}},
		LargeBlob: &LargeBlobInputs{Write: []byte("blob")},
	}))
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{
		"appid": "https://example.org",
		"prf": map[string]any{"evalByCredential": map[string]any{
			b64.EncodeToString(cred.ID): map[string]any{"first": "YQ", "second": "Yg"},
		}},
		"largeBlob": map[string]any{"write": b64.EncodeToString([]byte("blob"))},
	}
	if got := extensionsJSON(t, ropts); !jsonEqual(got, want) {
		t.Fatalf("login extensions = %v", got)
	}
}

func extensionsJSON(t *testing.T, opts any) any {
	t.Helper()
	data, _ := json.Marshal(opts)
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m["extensions"]
}

func TestExtensionInputsRejected(t *testing.T) {
	rp := newTestRP(t, Config{}, newMemStore())
	one := []Credential{{ID: []byte("cred-1"), Subject: "u-1", UserHandle: []byte("h")}}
	two := append(one, Credential{ID: []byte("cred-2"), Subject: "u-1", UserHandle: []byte("h")})
	byCred := func(id string) *PRFInputs {
		return &PRFInputs{EvalByCredential: map[string]PRFValues{id: {First: []byte("a")}}}
	}
	for name, begin := range map[string]func() error{
		"credProps at login": func() error {
			_, _, err := rp.BeginLogin(one, WithExtensions(ExtensionInputs{CredProps: true}))
			return err
		},
		"appid at registration": func() error {
			_, _, err := rp.BeginRegistration(testUser, nil, WithExtensions(ExtensionInputs{AppID: "https://example.org"}))
			return err
		},
		"appid not https": func() error {
			_, _, err := rp.BeginLogin(one, WithExtensions(ExtensionInputs{AppID: "http://example.org"}))
			return err
		},
		"evalByCredential at registration": func() error {
			_, _, err := rp.BeginRegistration(testUser, nil, WithExtensions(ExtensionInputs{PRF: byCred(b64.EncodeToString([]byte("cred-1")))}))
			return err
		},
		"evalByCredential for another credential": func() error {
			_, _, err := rp.BeginLogin(one, WithExtensions(ExtensionInputs{PRF: byCred(b64.EncodeToString([]byte("cred-2")))}))
			return err
		},
		"evalByCredential with a padded ID": func() error {
			_, _, err := rp.BeginLogin(one, WithExtensions(ExtensionInputs{PRF: byCred(b64.EncodeToString([]byte("cred-1")) + "=")}))
			return err
		},
		"evalByCredential in a discoverable login": func() error {
			_, _, err := rp.BeginDiscoverableLogin(WithExtensions(ExtensionInputs{PRF: byCred(b64.EncodeToString([]byte("cred-1")))}))
			return err
		},
		"largeBlob read at registration": func() error {
			_, _, err := rp.BeginRegistration(testUser, nil, WithExtensions(ExtensionInputs{LargeBlob: &LargeBlobInputs{Read: true}}))
			return err
		},
		"unknown largeBlob support": func() error {
			_, _, err := rp.BeginRegistration(testUser, nil, WithExtensions(ExtensionInputs{LargeBlob: &LargeBlobInputs{Support: "always"}}))
			return err
		},
		"largeBlob support at login": func() error {
			_, _, err := rp.BeginLogin(one, WithExtensions(ExtensionInputs{LargeBlob: &LargeBlobInputs{Support: LargeBlobRequired, Read: true}}))
			return err
		},
		"largeBlob read and write": func() error {
			_, _, err := rp.BeginLogin(one, WithExtensions(ExtensionInputs{LargeBlob: &LargeBlobInputs{Read: true, Write: []byte("x")}}))
			return err
		},
		"largeBlob without read or write": func() error {
			_, _, err := rp.BeginLogin(one, WithExtensions(ExtensionInputs{LargeBlob: &LargeBlobInputs{}}))
			return err
		},
		"largeBlob write with two credentials": func() error {
			_, _, err := rp.BeginLogin(two, WithExtensions(ExtensionInputs{LargeBlob: &LargeBlobInputs{Write: []byte("x")}}))
			return err
		},
	} {
		if begin() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

var prfOutput = bytes.Repeat([]byte{7}, 32)

func TestRegistrationExtensionOutputs(t *testing.T) {
	ctx := context.Background()
	all := WithExtensions(ExtensionInputs{CredProps: true, PRF: &PRFInputs{Eval: &PRFValues{First: []byte("salt")}}, LargeBlob: &LargeBlobInputs{}})
	clientExt := map[string]any{
		"credProps": map[string]any{"rk": true},
		"prf":       map[string]any{"enabled": true, "results": map[string]any{"first": b64.EncodeToString(prfOutput)}},
		"largeBlob": map[string]any{"supported": false},
		"appid":     true,
	}
	for _, tc := range []struct {
		name      string
		opts      []CeremonyOption
		clientExt map[string]any
		want      ExtensionOutputs
		err       error
	}{
		{"requested", []CeremonyOption{all}, clientExt, ExtensionOutputs{
			Discoverable: ptr(true), PRFEnabled: ptr(true), PRFResults: &PRFValues{First: prfOutput}, LargeBlobSupported: ptr(false),
		}, nil},
		{"not requested", nil, clientExt, ExtensionOutputs{}, nil},
		{"absent", []CeremonyOption{all}, nil, ExtensionOutputs{}, nil},
		{"malformed and not requested", nil, map[string]any{"credProps": 5, "prf": "x"}, ExtensionOutputs{}, nil},
		{"malformed credProps", []CeremonyOption{all}, map[string]any{"credProps": map[string]any{"rk": "yes"}}, ExtensionOutputs{}, ErrMalformed},
		{"malformed largeBlob", []CeremonyOption{all}, map[string]any{"largeBlob": map[string]any{"blob": "!"}}, ExtensionOutputs{}, ErrMalformed},
		{"short PRF output", []CeremonyOption{all}, map[string]any{"prf": map[string]any{"results": map[string]any{"first": "AAAA"}}}, ExtensionOutputs{}, ErrMalformed},
		{"PRF output without first", []CeremonyOption{all}, map[string]any{"prf": map[string]any{"results": map[string]any{}}}, ExtensionOutputs{}, ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp := newTestRP(t, Config{}, newMemStore())
			a := newSoftAuthenticator(t)
			a.clientExt = tc.clientExt
			a.flags |= flagED
			a.trailing = cborEnc(cborPairs{{"credProtect", 2}, {"hmac-secret", true}})
			_, ch, err := rp.BeginRegistration(testUser, nil, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			reg, err := rp.FinishRegistration(ctx, ch, a.create(ch))
			if tc.err != nil {
				if !errors.Is(err, tc.err) || !errors.Is(err, authent.ErrUnauthenticated) {
					t.Fatalf("FinishRegistration = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.want.Authenticator = map[string]any{"credProtect": int64(2), "hmac-secret": true}
			if !reflect.DeepEqual(reg.Extensions, tc.want) {
				t.Fatalf("Extensions = %+v, want %+v", reg.Extensions, tc.want)
			}
		})
	}
}

func TestLoginExtensionOutputs(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	rp := newTestRP(t, Config{}, store)
	a := newSoftAuthenticator(t)
	cred := register(t, rp, store, a)
	_, ch, err := rp.BeginLogin([]Credential{cred}, WithExtensions(ExtensionInputs{
		PRF:       &PRFInputs{Eval: &PRFValues{First: []byte("a"), Second: []byte("b")}},
		LargeBlob: &LargeBlobInputs{Read: true},
	}))
	if err != nil {
		t.Fatal(err)
	}
	a.signCount = 1
	a.clientExt = map[string]any{
		"prf":       map[string]any{"results": map[string]any{"first": b64.EncodeToString(prfOutput), "second": b64.EncodeToString(prfOutput[:31])}},
		"largeBlob": map[string]any{"blob": b64.EncodeToString([]byte("blob"))},
	}
	if _, err := rp.FinishLogin(ctx, ch, a.get(ch)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("FinishLogin with a short second PRF output = %v, want ErrMalformed", err)
	}
	a.clientExt["prf"] = map[string]any{"results": map[string]any{"first": b64.EncodeToString(prfOutput), "second": b64.EncodeToString(prfOutput)}}
	a.flags |= flagED
	a.trailing = cborEnc(cborPairs{{"hmac-secret", []byte("encrypted")}, {"ext", cborPairs{{1, []any{"x"}}}}})
	login, err := rp.FinishLogin(ctx, ch, a.get(ch))
	if err != nil {
		t.Fatal(err)
	}
	want := ExtensionOutputs{
		PRFResults: &PRFValues{First: prfOutput, Second: prfOutput},
		LargeBlob:  []byte("blob"),
		Authenticator: map[string]any{
			"hmac-secret": []byte("encrypted"),
			"ext":         map[any]any{int64(1): []any{"x"}},
		},
	}
	if !reflect.DeepEqual(login.Extensions, want) {
		t.Fatalf("Extensions = %+v, want %+v", login.Extensions, want)
	}
}

func TestAppID(t *testing.T) {
	ctx := context.Background()
	const appID = "https://example.org/u2f"
	for _, tc := range []struct {
		name      string
		request   bool
		reported  bool
		signedFor string
		want      error
	}{
		{"used", true, true, appID, nil},
		{"requested, RP ID used", true, false, "example.org", nil},
		{"not requested", false, true, appID, ErrRPID},
		{"not reported", true, false, appID, ErrRPID},
		{"reported, RP ID signed", true, true, "example.org", ErrRPID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			rp := newTestRP(t, Config{}, store)
			a := newSoftAuthenticator(t)
			cred := Credential{ID: a.credID, Subject: "u-1", UserHandle: testUser.Handle, PublicKey: a.coseKey(), Algorithm: ES256}
			store.put(cred)
			var opts []CeremonyOption
			if tc.request {
				opts = append(opts, WithExtensions(ExtensionInputs{AppID: appID}))
			}
			_, ch, err := rp.BeginLogin([]Credential{cred}, opts...)
			if err != nil {
				t.Fatal(err)
			}
			a.rpID = tc.signedFor
			a.flags = flagUP
			a.clientExt = map[string]any{"appid": tc.reported}
			login, err := rp.FinishLogin(ctx, ch, a.get(ch))
			if !errors.Is(err, tc.want) {
				t.Fatalf("FinishLogin = %v, want %v", err, tc.want)
			}
			if err == nil && login.Extensions.AppIDUsed != tc.reported {
				t.Fatalf("AppIDUsed = %v, want %v", login.Extensions.AppIDUsed, tc.reported)
			}
		})
	}
}

// The outputs a request cannot produce follow from the client extension
// processing of prf (WebAuthn L3 §10.1.4) and largeBlob (§10.1.5).
func TestExtensionOutputsNotRequested(t *testing.T) {
	ctx := context.Background()
	out32 := b64.EncodeToString(prfOutput)
	type outputs = map[string]any
	for _, tc := range []struct {
		name      string
		login     bool
		in        ExtensionInputs
		clientExt map[string]any
		want      error
	}{
		{"largeBlob blob at registration", false, ExtensionInputs{LargeBlob: &LargeBlobInputs{Support: LargeBlobPreferred}},
			outputs{"largeBlob": outputs{"supported": false, "blob": "eA"}}, ErrMalformed},
		{"largeBlob written at registration", false, ExtensionInputs{LargeBlob: &LargeBlobInputs{}},
			outputs{"largeBlob": outputs{"written": true}}, ErrMalformed},
		{"largeBlob blob after a write", true, ExtensionInputs{LargeBlob: &LargeBlobInputs{Write: []byte("x")}},
			outputs{"largeBlob": outputs{"blob": "eA"}}, ErrMalformed},
		{"largeBlob written after a read", true, ExtensionInputs{LargeBlob: &LargeBlobInputs{Read: true}},
			outputs{"largeBlob": outputs{"written": true}}, ErrMalformed},
		{"largeBlob supported at login", true, ExtensionInputs{LargeBlob: &LargeBlobInputs{Read: true}},
			outputs{"largeBlob": outputs{"supported": true}}, ErrMalformed},
		{"prf results without eval", false, ExtensionInputs{PRF: &PRFInputs{}},
			outputs{"prf": outputs{"enabled": true, "results": outputs{"first": out32}}}, ErrMalformed},
		{"prf second without a second input", false, ExtensionInputs{PRF: &PRFInputs{Eval: &PRFValues{First: []byte("a")}}},
			outputs{"prf": outputs{"results": outputs{"first": out32, "second": out32}}}, ErrMalformed},
		{"prf second at login without a second input", true, ExtensionInputs{PRF: &PRFInputs{Eval: &PRFValues{First: []byte("a")}}},
			outputs{"prf": outputs{"results": outputs{"first": out32, "second": out32}}}, ErrMalformed},
		{"prf enabled at login", true, ExtensionInputs{PRF: &PRFInputs{Eval: &PRFValues{First: []byte("a")}}},
			outputs{"prf": outputs{"enabled": true}}, ErrMalformed},
		{"prf second from the credential's own input", true, ExtensionInputs{PRF: &PRFInputs{
			Eval:             &PRFValues{First: []byte("a")},
			EvalByCredential: map[string]PRFValues{"": {First: []byte("b"), Second: []byte("c")}},
		}}, outputs{"prf": outputs{"results": outputs{"first": out32, "second": out32}}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			rp := newTestRP(t, Config{}, store)
			a := newSoftAuthenticator(t)
			a.clientExt = tc.clientExt
			var err error
			if tc.login {
				a.clientExt = nil
				cred := register(t, rp, store, a)
				if p := tc.in.PRF; p != nil && p.EvalByCredential != nil {
					p.EvalByCredential = map[string]PRFValues{b64.EncodeToString(cred.ID): p.EvalByCredential[""]}
				}
				_, ch, berr := rp.BeginLogin([]Credential{cred}, WithExtensions(tc.in))
				if berr != nil {
					t.Fatal(berr)
				}
				a.signCount, a.clientExt = 1, tc.clientExt
				_, err = rp.FinishLogin(ctx, ch, a.get(ch))
			} else {
				_, ch, berr := rp.BeginRegistration(testUser, nil, WithExtensions(tc.in))
				if berr != nil {
					t.Fatal(berr)
				}
				_, err = rp.FinishRegistration(ctx, ch, a.create(ch))
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestChallengeWithExtensionListDoesNotDecode(t *testing.T) {
	old := `{"ceremony":"webauthn.get","challenge":"AAAA","expiresAt":"2026-06-01T12:05:00Z","extensions":["prf"],"appid":"https://example.org"}`
	var ch Challenge
	if err := json.Unmarshal([]byte(old), &ch); err == nil {
		t.Fatalf("decoded %+v", ch)
	}
}

func ptr[T any](v T) *T { return &v }

func FuzzClientExtensionOutputs(f *testing.F) {
	f.Add([]byte(`{"credProps":{"rk":true},"prf":{"enabled":true,"results":{"first":"` + b64.EncodeToString(prfOutput) + `"}},"largeBlob":{"blob":"AA","written":true},"appid":true}`))
	ch := Challenge{Ceremony: ceremonyGet, Extensions: ExtensionInputs{
		PRF:       &PRFInputs{Eval: &PRFValues{First: []byte("a"), Second: []byte("b")}},
		LargeBlob: &LargeBlobInputs{Read: true},
		AppID:     "https://example.org",
	}}
	f.Fuzz(func(t *testing.T, data []byte) {
		var raw map[string]jsontext.Value
		if json.Unmarshal(data, &raw) != nil {
			return
		}
		out, err := parseClientOutputs(raw, ch, []byte("cred"))
		if err == nil && out.PRFResults != nil && len(out.PRFResults.First) != prfOutputSize {
			t.Fatalf("accepted a %d-byte PRF output", len(out.PRFResults.First))
		}
	})
}
