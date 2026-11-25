package oidc

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/tohshi/authent"
)

var (
	// ErrNoUserInfoEndpoint means the provider does not advertise a
	// userinfo_endpoint.
	ErrNoUserInfoEndpoint = errors.New("oidc: provider has no userinfo endpoint")
	// ErrUserInfoRejected means the UserInfo endpoint rejected the access
	// token (401 or 403), for example because it expired, was revoked or
	// lacks the openid scope. It wraps authent.ErrUnauthenticated.
	ErrUserInfoRejected = fmt.Errorf("oidc: userinfo request rejected: %w", authent.ErrUnauthenticated)
	// ErrInvalidUserInfo means the UserInfo response must not be used: it
	// is malformed, has an unsupported content type, or its "sub" does not
	// match the ID token. It wraps authent.ErrUnauthenticated.
	ErrInvalidUserInfo = fmt.Errorf("oidc: invalid userinfo response: %w", authent.ErrUnauthenticated)
)

// UserInfo is a verified UserInfo response.
type UserInfo struct {
	// Subject equals the "sub" of the ID token.
	Subject string
	// Claims holds all claims of the response, including "sub", with JSON
	// types (numbers are float64).
	Claims map[string]any
}

const maxUserInfoSize = 1 << 20

// UserInfo fetches claims about the end-user from the provider's UserInfo
// endpoint (OpenID Connect Core §5.3) using token's access token.
//
// subject must be the "sub" of the ID token the access token was issued
// with, for example Result.Principal.Subject. A response for any other
// subject is rejected with ErrInvalidUserInfo, which prevents token
// substitution (OpenID Connect Core §5.3.2).
//
// Only plain JSON responses are supported; signed or encrypted responses
// (application/jwt) are rejected. Redirects are not followed, so the
// access token is only ever sent to the advertised endpoint.
//
// Errors from the network, or statuses other than 200, 401 and 403, are
// not authentication failures and do not wrap authent.ErrUnauthenticated.
func (c *Client) UserInfo(ctx context.Context, token *oauth2.Token, subject string) (*UserInfo, error) {
	endpoint := c.provider.UserinfoEndpoint
	if endpoint == "" {
		return nil, ErrNoUserInfoEndpoint
	}
	if token == nil || token.AccessToken == "" {
		return nil, errors.New("oidc: userinfo: access token is required")
	}
	if typ := token.Type(); typ != "Bearer" {
		return nil, fmt.Errorf("oidc: userinfo: unsupported token type %q", typ)
	}
	if subject == "" {
		return nil, errors.New("oidc: userinfo: subject is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	token.SetAuthHeader(req)
	req.Header.Set("Accept", "application/json")

	hc := *c.client
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: userinfo: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("%w: status %s", ErrUserInfoRejected, resp.Status)
	default:
		return nil, fmt.Errorf("oidc: userinfo: status %s", resp.Status)
	}

	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: content type: %v", ErrInvalidUserInfo, err)
	case mediaType == "application/jwt":
		return nil, fmt.Errorf("%w: signed or encrypted responses are not supported", ErrInvalidUserInfo)
	case mediaType != "application/json":
		return nil, fmt.Errorf("%w: content type %q", ErrInvalidUserInfo, mediaType)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUserInfoSize+1))
	if err != nil {
		return nil, fmt.Errorf("oidc: userinfo: %w", err)
	}
	if len(body) > maxUserInfoSize {
		return nil, errors.New("oidc: userinfo response too large")
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUserInfo, err)
	}
	if claims == nil {
		return nil, fmt.Errorf("%w: not a JSON object", ErrInvalidUserInfo)
	}
	sub, _ := claims["sub"].(string)
	if sub != subject {
		return nil, fmt.Errorf("%w: sub %q does not match the ID token", ErrInvalidUserInfo, sub)
	}
	return &UserInfo{Subject: sub, Claims: claims}, nil
}
