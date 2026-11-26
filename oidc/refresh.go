package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

// ErrRefreshRejected means the provider rejected the refresh token, for
// example because it expired, was revoked or was already rotated; the
// user has to log in again. It wraps authent.ErrUnauthenticated.
var ErrRefreshRejected = fmt.Errorf("oidc: refresh rejected: %w", authent.ErrUnauthenticated)

// Refresh obtains new tokens with prev's refresh token (OpenID Connect
// Core §12). The client authenticates as in Exchange, including with
// private_key_jwt, and with Config.DPoP the request carries a proof and a
// Bearer access token is refused. prev is the Result of Exchange or of an
// earlier Refresh. Store the returned Result in its place: the provider
// may have rotated the refresh token.
//
// A new ID token in the response is verified like the one from Exchange,
// and must describe the same authentication as prev's (§12.2): the same
// "iss", "sub", "aud" and "azp", the same "auth_time" if it has one, and
// the same "nonce" if it has one. Without a new ID token, the result
// keeps prev's.
//
// A refresh token rejected with a 4xx status wraps ErrRefreshRejected.
// Network errors and 5xx statuses do not wrap authent.ErrUnauthenticated.
func (c *Client) Refresh(ctx context.Context, prev *Result) (*Result, error) {
	if prev == nil || prev.Token == nil || prev.Token.RefreshToken == "" {
		return nil, errors.New("oidc: refresh: no refresh token")
	}
	if prev.IDToken == nil {
		return nil, errors.New("oidc: refresh: the previous ID token is required")
	}
	src := c.oauth.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, c.client),
		&oauth2.Token{RefreshToken: prev.Token.RefreshToken})
	tok, err := src.Token()
	if err != nil {
		if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok && re.Response != nil &&
			re.Response.StatusCode >= http.StatusBadRequest && re.Response.StatusCode < http.StatusInternalServerError {
			return nil, fmt.Errorf("%w: %w", ErrRefreshRejected, err)
		}
		return nil, fmt.Errorf("oidc: refresh: %w", err)
	}
	if err := c.checkTokenType(tok); err != nil {
		return nil, err
	}

	res := &Result{Principal: prev.Principal, IDToken: prev.IDToken, RawIDToken: prev.RawIDToken, Token: tok}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return res, nil
	}
	claims, header, err := c.idTokenVerifier.VerifyWithHeader(ctx, raw)
	if err != nil {
		return nil, err
	}
	if err := c.checkIDToken(claims, header, tok.AccessToken); err != nil {
		return nil, err
	}
	if err := checkRefreshedIDToken(prev.IDToken, claims); err != nil {
		return nil, err
	}
	if res.Principal, err = jwt.PrincipalFromClaims(claims, authent.MethodOIDC); err != nil {
		return nil, err
	}
	res.IDToken, res.RawIDToken = claims, raw
	return res, nil
}

func checkRefreshedIDToken(prev, next *jwt.Claims) error {
	mismatch := func(claim string) error {
		return fmt.Errorf("%w: refreshed %s differs from the original", ErrInvalidIDToken, claim)
	}
	if next.Issuer != prev.Issuer {
		return mismatch("iss")
	}
	if next.Subject != prev.Subject {
		return mismatch("sub")
	}
	if !sameSet(next.Audience, prev.Audience) {
		return mismatch("aud")
	}
	prevAzp, prevHasAzp := prev.Extra["azp"].(string)
	nextAzp, nextHasAzp := next.Extra["azp"].(string)
	if _, present := next.Extra["azp"]; present != prevHasAzp || nextHasAzp != prevHasAzp || nextAzp != prevAzp {
		return mismatch("azp")
	}
	if nonce, present := next.Extra["nonce"]; present {
		got, _ := nonce.(string)
		want, _ := prev.Extra["nonce"].(string)
		if got == "" || got != want {
			return mismatch("nonce")
		}
	}
	nextAuth, err := next.AuthTime()
	if err != nil {
		return err
	}
	if !nextAuth.IsZero() {
		if prevAuth, err := prev.AuthTime(); err != nil || !nextAuth.Equal(prevAuth) {
			return mismatch("auth_time")
		}
	}
	return nil
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}
