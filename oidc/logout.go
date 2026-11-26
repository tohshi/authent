package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
)

var (
	// ErrNoEndSessionEndpoint means the provider does not advertise an
	// end_session_endpoint.
	ErrNoEndSessionEndpoint = errors.New("oidc: provider has no end_session_endpoint")
	// ErrInvalidLogout means a front-channel logout request or a
	// back-channel logout token must not be acted on. Respond with 400.
	// It wraps authent.ErrUnauthenticated.
	ErrInvalidLogout = fmt.Errorf("oidc: invalid logout request: %w", authent.ErrUnauthenticated)
)

const (
	logoutTokenType   = "logout+jwt"
	logoutEvent       = "http://schemas.openid.net/event/backchannel-logout"
	maxLogoutTokenAge = 2 * time.Minute
)

// EndSession is an RP-initiated logout request.
type EndSession struct {
	// IDTokenHint is the session's raw ID token, Result.RawIDToken. It is
	// recommended: without it, providers may ask the user to confirm and
	// may not redirect back.
	IDTokenHint string
	// PostLogoutRedirectURI is where the provider sends the user after
	// logging out. It must be registered with the provider.
	PostLogoutRedirectURI string
	// State is passed back to PostLogoutRedirectURI unchanged in the
	// "state" query parameter. It requires PostLogoutRedirectURI.
	State string
}

// EndSessionURL returns the URL of the provider's end_session_endpoint for
// the request. End the local session, then redirect the user there to log
// out at the provider too. It fails with ErrNoEndSessionEndpoint if the
// provider has none.
func (c *Client) EndSessionURL(r EndSession) (string, error) {
	if c.provider.EndSessionEndpoint == "" {
		return "", ErrNoEndSessionEndpoint
	}
	if r.State != "" && r.PostLogoutRedirectURI == "" {
		return "", errors.New("oidc: end session: state requires a post-logout redirect URI")
	}
	u, err := url.Parse(c.provider.EndSessionEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", c.oauth.ClientID)
	for name, value := range map[string]string{
		"id_token_hint":            r.IDTokenHint,
		"post_logout_redirect_uri": r.PostLogoutRedirectURI,
		"state":                    r.State,
	} {
		if value != "" {
			q.Set(name, value)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Logout names the provider sessions that ended. End every local session
// whose ID token it Matches.
type Logout struct {
	Issuer string
	// Subject is the "sub" of a back-channel logout token. It is empty if
	// the token names only a session, and for front-channel logout.
	Subject string
	// SessionID is the provider's session ID, the "sid" claim of the ID
	// tokens issued for that session. It is empty if a back-channel logout
	// token names only a subject, which ends all of the subject's sessions.
	SessionID string
}

// Matches reports whether the session that idToken was issued for has
// ended: the issuers are equal, and so are the subject and the session ID
// where l names them.
func (l Logout) Matches(idToken *jwt.Claims) bool {
	if idToken == nil || idToken.Issuer != l.Issuer {
		return false
	}
	if l.Subject != "" && idToken.Subject != l.Subject {
		return false
	}
	sid, _ := idToken.Extra["sid"].(string)
	return l.SessionID == "" || sid == l.SessionID
}

// FrontChannelLogout checks the query parameters of a request to the
// client's frontchannel_logout_uri. Register the client with
// frontchannel_logout_session_required: the request must carry exactly
// one "iss", equal to the provider's issuer, and one non-empty "sid".
// Without them, any site could log users out by embedding the URI.
// Respond with Cache-Control: no-store.
func (c *Client) FrontChannelLogout(query url.Values) (*Logout, error) {
	iss, sid := query["iss"], query["sid"]
	if len(iss) != 1 || len(sid) != 1 || sid[0] == "" {
		return nil, fmt.Errorf("%w: exactly one iss and one sid are required", ErrInvalidLogout)
	}
	if iss[0] != c.provider.Issuer {
		return nil, fmt.Errorf("%w: issuer %q", ErrInvalidLogout, iss[0])
	}
	return &Logout{Issuer: iss[0], SessionID: sid[0]}, nil
}

// BackChannelLogout verifies a logout token, the "logout_token" form
// parameter of a POST to the client's backchannel_logout_uri. Respond
// with 200 once the matching sessions have ended and with 400 if
// verification fails, in both cases with Cache-Control: no-store.
//
// The token is verified like an ID token, and must also have the "typ"
// header logout+jwt, the back-channel logout event, a "sub" or "sid", no
// "nonce", an "iat" at most two minutes old (plus the leeway), and a "jti"
// not seen before by Config.ReplayCache. The jti is recorded once every
// check has passed, so a token is accepted only once, even if ending the
// sessions then fails.
//
// Rejections wrap ErrInvalidLogout or a jwt error, and
// authent.ErrUnauthenticated. Errors from the key set or the replay cache
// do not.
func (c *Client) BackChannelLogout(ctx context.Context, logoutToken string) (*Logout, error) {
	claims, err := c.logoutVerifier.Verify(ctx, logoutToken)
	if err != nil {
		return nil, err
	}
	events, _ := claims.Extra["events"].(map[string]any)
	if _, ok := events[logoutEvent].(map[string]any); !ok {
		return nil, fmt.Errorf("%w: no back-channel logout event", ErrInvalidLogout)
	}
	if _, ok := claims.Extra["nonce"]; ok {
		return nil, fmt.Errorf("%w: nonce present", ErrInvalidLogout)
	}
	sid, isString := claims.Extra["sid"].(string)
	if _, ok := claims.Extra["sid"]; ok && (!isString || sid == "") {
		return nil, fmt.Errorf("%w: invalid sid", ErrInvalidLogout)
	}
	if claims.Subject == "" && sid == "" {
		return nil, fmt.Errorf("%w: neither sub nor sid", ErrInvalidLogout)
	}
	// Verified again, recording the jti, only now that every check has
	// passed, so that a rejected token does not use up its jti.
	if _, err := c.logoutReplay.Verify(ctx, logoutToken); err != nil {
		return nil, err
	}
	return &Logout{Issuer: claims.Issuer, Subject: claims.Subject, SessionID: sid}, nil
}
