package dpop

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// Transport is an http.RoundTripper that adds a fresh DPoP proof to every
// request.
//
// With Source set it also sends the access token in the Authorization
// header with the DPoP scheme and binds each proof to it, for requests to
// resource servers. Without Source it only adds proofs, for requests to an
// authorization server's token and pushed authorization request endpoints.
//
// It records DPoP-Nonce response headers in the Prover. When a server
// rejects a request because it requires a new nonce (error
// "use_dpop_nonce", RFC 9449 §8 and §9), the request is retried once with
// the new nonce, provided its body can be replayed (http.NewRequest sets
// GetBody for common body types).
type Transport struct {
	// Prover signs the proofs. It is required.
	Prover *Prover
	// Source supplies DPoP-bound access tokens. Tokens whose type is not
	// DPoP are refused rather than sent.
	Source oauth2.TokenSource
	// Base is the underlying transport. The default is
	// http.DefaultTransport.
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	bodyClosed := false
	if req.Body != nil {
		defer func() {
			if !bodyClosed {
				req.Body.Close()
			}
		}()
	}
	if t.Prover == nil {
		return nil, errors.New("dpop: Transport.Prover is nil")
	}
	var accessToken string
	if t.Source != nil {
		tok, err := t.Source.Token()
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(tok.TokenType, TokenType) {
			return nil, fmt.Errorf("dpop: refusing to send a %q token as a DPoP token", tok.TokenType)
		}
		accessToken = tok.AccessToken
	}

	uri := req.URL.String()
	r, err := t.prepare(req, req.Body, uri, accessToken)
	if err != nil {
		return nil, err
	}
	bodyClosed = true // the base transport closes it from here on
	resp, err := t.base().RoundTrip(r)
	if err != nil {
		return nil, err
	}
	t.recordNonce(uri, resp)
	canReplay := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
	if !canReplay || !nonceChallenge(resp) {
		return resp, nil
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	var body io.ReadCloser
	if req.GetBody != nil {
		if body, err = req.GetBody(); err != nil {
			return nil, err
		}
	}
	if r, err = t.prepare(req, body, uri, accessToken); err != nil {
		if body != nil {
			body.Close()
		}
		return nil, err
	}
	resp, err = t.base().RoundTrip(r)
	if err != nil {
		return nil, err
	}
	t.recordNonce(uri, resp)
	return resp, nil
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// prepare clones req with body and a new proof. A RoundTripper must not
// modify the caller's request.
func (t *Transport) prepare(req *http.Request, body io.ReadCloser, uri, accessToken string) (*http.Request, error) {
	proof, err := t.Prover.Proof(req.Method, uri, accessToken)
	if err != nil {
		return nil, err
	}
	r := req.Clone(req.Context())
	r.Body = body
	r.Header.Set(HeaderName, proof)
	if accessToken != "" {
		r.Header.Set("Authorization", TokenType+" "+accessToken)
	}
	return r, nil
}

func (t *Transport) recordNonce(uri string, resp *http.Response) {
	if n := resp.Header.Get(NonceHeaderName); n != "" {
		t.Prover.SetNonce(uri, n)
	}
}

// nonceChallenge reports whether resp asks for a retry with the nonce it
// supplies: a 400 token endpoint error or a 401 resource server challenge
// with the error "use_dpop_nonce".
func nonceChallenge(resp *http.Response) bool {
	if resp.Header.Get(NonceHeaderName) == "" {
		return false
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		for _, v := range resp.Header.Values("WWW-Authenticate") {
			if strings.Contains(v, "use_dpop_nonce") {
				return true
			}
		}
	case http.StatusBadRequest:
		// Peek at the error response and put it back for the caller.
		buf, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body}
		var e struct {
			Error string `json:"error"`
		}
		return err == nil && json.Unmarshal(buf, &e) == nil && e.Error == "use_dpop_nonce"
	}
	return false
}
