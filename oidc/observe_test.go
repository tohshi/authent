package oidc

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/internal/observetest"
	"github.com/tohshi/authent/jwt"
)

func TestObserver(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	rec := &observetest.Recorder{}
	c := newClient(t, p, func(cfg *Config) { cfg.Observer = rec })

	req, _ := c.AuthCodeURL()
	state, code := p.authorize(t, req.URL)
	res, err := c.Exchange(ctx, req, state, code)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Exchange(ctx, req, state, code)
	_, _ = c.Exchange(ctx, req, "forged", code)
	req2, _ := c.AuthCodeURL()
	state2, code2 := p.authorize(t, req2.URL)
	p.mutate = func(c *jwt.Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-2 * time.Minute)) }
	_, _ = c.Exchange(ctx, req2, state2, code2)
	p.mutate = nil

	next, err := c.Refresh(ctx, res)
	if err != nil {
		t.Fatal(err)
	}
	stale := *res
	stale.Token = &oauth2.Token{RefreshToken: "unknown-refresh-token"}
	_, _ = c.Refresh(ctx, &stale)

	logout := signLogoutToken(t, p.signerKey, logoutTokenType, validLogoutClaims(p))
	_, _ = c.BackChannelLogout(ctx, logout)
	_, _ = c.BackChannelLogout(ctx, logout)

	auth := func(o authent.Outcome, r authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindAuthentication, Method: authent.MethodOIDC, Outcome: o, Reason: r, Subject: sub}
	}
	tv := func(o authent.Outcome, r authent.Reason, sub string) authent.Event {
		return authent.Event{Kind: authent.KindTokenVerification, Method: authent.MethodOIDC, Outcome: o, Reason: r, Subject: sub}
	}
	rec.Expect(t, []authent.Event{
		auth(authent.OutcomeSuccess, "", "user-42"),
		auth(authent.OutcomeRejected, authent.ReasonProviderRejected, ""),
		auth(authent.OutcomeRejected, authent.ReasonStateMismatch, ""),
		auth(authent.OutcomeRejected, authent.ReasonExpired, ""),
		auth(authent.OutcomeSuccess, "", "user-42"),
		auth(authent.OutcomeRejected, authent.ReasonProviderRejected, ""),
		tv(authent.OutcomeSuccess, "", "user-42"),
		tv(authent.OutcomeRejected, authent.ReasonReplayed, ""),
	}, code, code2, state, req.Nonce, req.CodeVerifier, res.RawIDToken, res.Token.AccessToken,
		res.Token.RefreshToken, next.Token.AccessToken, logout, clientSecret)
}
