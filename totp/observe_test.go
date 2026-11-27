package totp

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observetest"
)

func flipLastDigit(code string) string {
	b := []byte(code)
	b[len(b)-1] = '0' + (b[len(b)-1]-'0'+1)%10
	return string(b)
}

func TestObserver(t *testing.T) {
	ctx := context.Background()
	rec := &observetest.Recorder{}
	ev := func(m authent.Method, o authent.Outcome, r authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindAuthentication, Method: m, Outcome: o, Reason: r, Subject: sub}
	}

	k, _ := GenerateKey()
	store := &fakeStore{creds: map[string]Credential{"u1": {Subject: "u1", Key: k}}}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	a, err := NewAuthenticator(store, WithClock(func() time.Time { return now }), WithObserver(rec))
	if err != nil {
		t.Fatal(err)
	}
	code, _ := k.Code(now)
	_, _ = a.Authenticate(ctx, "u1", code)
	_, _ = a.Authenticate(ctx, "u1", code)
	_, _ = a.Authenticate(ctx, "u1", flipLastDigit(code))
	_, _ = a.Authenticate(ctx, "u2", code)
	store.err = errors.New("store down")
	_, _ = a.Authenticate(ctx, "u1", code)
	rec.Expect(t, []authent.Event{
		ev(authent.MethodTOTP, authent.OutcomeSuccess, "", "u1"),
		ev(authent.MethodTOTP, authent.OutcomeRejected, authent.ReasonReplayed, ""),
		ev(authent.MethodTOTP, authent.OutcomeRejected, authent.ReasonInvalidCredentials, ""),
		ev(authent.MethodTOTP, authent.OutcomeRejected, authent.ReasonNotEnrolled, ""),
		ev(authent.MethodTOTP, authent.OutcomeError, "", ""),
	}, code, flipLastDigit(code), k.EncodedSecret(), string(k.Secret))

	h, _ := newHOTP(t, 0, WithHOTPObserver(rec))
	hk := rfc4226Key()
	_, _ = h.Authenticate(ctx, "u1", hk.hotp(0))
	_, _ = h.Authenticate(ctx, "u1", hk.hotp(0))
	_, _ = h.Resync(ctx, "u1", hk.hotp(30), hk.hotp(31))
	rec.Expect(t, []authent.Event{
		ev(authent.MethodHOTP, authent.OutcomeSuccess, "", "u1"),
		ev(authent.MethodHOTP, authent.OutcomeRejected, authent.ReasonInvalidCredentials, ""),
		ev(authent.MethodHOTP, authent.OutcomeSuccess, "", "u1"),
	}, hk.hotp(0), hk.hotp(30), hk.hotp(31), hk.EncodedSecret(), string(hk.Secret))

	codes, hashes, err := GenerateRecoveryCodes(2)
	if err != nil {
		t.Fatal(err)
	}
	rstore := &recoveryStore{unused: map[string]map[RecoveryCodeHash]bool{"u1": {hashes[0]: true, hashes[1]: true}}}
	r, err := NewRecoveryAuthenticator(rstore, WithRecoveryObserver(rec))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = r.Authenticate(ctx, "u1", codes[0])
	_, _ = r.Authenticate(ctx, "u1", codes[0])
	_, _ = r.Authenticate(ctx, "u1", "not a code")
	rstore.err = errors.New("store down")
	_, _ = r.Authenticate(ctx, "u1", codes[1])
	rec.Expect(t, []authent.Event{
		ev(authent.MethodRecovery, authent.OutcomeSuccess, "", "u1"),
		ev(authent.MethodRecovery, authent.OutcomeRejected, authent.ReasonInvalidCredentials, ""),
		ev(authent.MethodRecovery, authent.OutcomeRejected, authent.ReasonInvalidCredentials, ""),
		ev(authent.MethodRecovery, authent.OutcomeError, "", ""),
	}, codes[0], codes[1], hex.EncodeToString(hashes[0][:]), string(hashes[0][:]))
}
