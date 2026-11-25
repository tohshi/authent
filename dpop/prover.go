package dpop

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tohshi/authent/jwt"
)

// maxNonceOrigins bounds the nonces a Prover remembers. When it is
// exceeded, all remembered nonces are dropped; servers that need one
// simply ask again.
const maxNonceOrigins = 256

// Prover creates DPoP proofs with one key pair. It also remembers the
// latest nonce each server provided, so that later proofs for that server
// include it. It is safe for concurrent use.
type Prover struct {
	signer *jwt.Signer
	alg    jwt.Algorithm
	jkt    string
	now    func() time.Time

	mu     sync.Mutex
	nonces map[string]string // origin -> nonce
}

// ProverOption configures a Prover.
type ProverOption func(*Prover)

// WithProverClock overrides the clock used for "iat", for tests.
func WithProverClock(now func() time.Time) ProverOption {
	return func(p *Prover) { p.now = now }
}

// NewProver returns a Prover that signs with key using alg, an asymmetric
// algorithm. key is *rsa.PrivateKey for RS*/PS*, *ecdsa.PrivateKey on the
// matching curve for ES*, or ed25519.PrivateKey for EdDSA.
//
// Tokens issued to the Prover are bound to its key, so keep the key for as
// long as the tokens (including refresh tokens) are used.
func NewProver(alg jwt.Algorithm, key any, opts ...ProverOption) (*Prover, error) {
	if alg.IsSymmetric() {
		return nil, fmt.Errorf("dpop: %q is not an asymmetric algorithm", alg)
	}
	signer, err := jwt.NewSigner(alg, key, jwt.WithType(proofType), jwt.WithJWKHeader())
	if err != nil {
		return nil, err
	}
	jkt, err := Thumbprint(signer.VerificationKey())
	if err != nil {
		return nil, err
	}
	p := &Prover{signer: signer, alg: alg, jkt: jkt, now: time.Now, nonces: map[string]string{}}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Algorithm returns the signing algorithm of the proofs.
func (p *Prover) Algorithm() jwt.Algorithm { return p.alg }

// Thumbprint returns the JWK SHA-256 thumbprint of the public key, which is
// the "jkt" that tokens issued to this Prover are bound to.
func (p *Prover) Thumbprint() string { return p.jkt }

// Proof returns a proof for a request with method to uri. Query and
// fragment of uri are left out of the proof. If accessToken is not empty,
// the proof is bound to it with the "ath" claim, as requests to resource
// servers require. The latest nonce recorded with SetNonce for uri's
// origin is included.
func (p *Prover) Proof(method, uri, accessToken string) (string, error) {
	if method == "" {
		return "", errors.New("dpop: empty method")
	}
	u, err := targetURI(uri)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	c := proofClaims{
		JTI:   base64.RawURLEncoding.EncodeToString(jti),
		HTM:   method,
		HTU:   u.String(),
		IAT:   jwt.NewNumericDate(p.now()),
		Nonce: p.nonce(origin(u)),
	}
	if accessToken != "" {
		c.ATH = AccessTokenHash(accessToken)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return p.signer.SignPayload(payload)
}

// SetNonce records nonce, the value of a DPoP-Nonce response header, for
// later proofs sent to uri's origin. Nonces are kept per origin because a
// nonce is only valid at the server that issued it (RFC 9449 §9). Values
// that are not valid nonces are ignored.
func (p *Prover) SetNonce(uri, nonce string) {
	u, err := targetURI(uri)
	if err != nil || !isNonce(nonce) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.nonces[origin(u)]; !ok && len(p.nonces) >= maxNonceOrigins {
		clear(p.nonces)
	}
	p.nonces[origin(u)] = nonce
}

func (p *Prover) nonce(origin string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.nonces[origin]
}
