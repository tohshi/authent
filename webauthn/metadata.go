package webauthn

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"
)

// MDS3URL is the location of the FIDO Metadata Service BLOB, which chains
// to GlobalSign Root CA - R3 (https://secure.globalsign.com/cacert/root-r3.crt).
const MDS3URL = "https://mds3.fidoalliance.org/"

const (
	maxMetadataSize = 64 << 20
	maxCRLSize      = 8 << 20
)

// MetadataSource looks up authenticator metadata by AAGUID. *Metadata
// implements it. To replace the BLOB while a RelyingParty runs, implement
// it with an atomic pointer to the current *Metadata.
type MetadataSource interface {
	Lookup(aaguid [16]byte) (MetadataEntry, bool)
}

// Metadata is a verified FIDO Metadata Service (MDS3) BLOB.
type Metadata struct {
	number     int
	nextUpdate time.Time
	entries    map[[16]byte]MetadataEntry
}

// MetadataEntry is the metadata of one authenticator model.
type MetadataEntry struct {
	AAGUID      [16]byte
	Description string
	// AttestationRoots are the trust anchors of the model's attestation.
	// Certificates that crypto/x509 cannot parse are left out.
	AttestationRoots []*x509.Certificate
	StatusReports    []StatusReport
	// Statement is the metadata statement as JSON, for the members this
	// package does not use.
	Statement jsontext.Value
}

// StatusReport is one entry of an authenticator model's status history.
type StatusReport struct {
	// Status is an AuthenticatorStatus value, such as "FIDO_CERTIFIED_L1"
	// or "REVOKED".
	Status        string
	EffectiveDate string
	// Certificate, if set, limits the report to attestations whose chain
	// contains it. A certificate that crypto/x509 cannot parse is treated
	// as absent, so the report applies to the whole model.
	Certificate *x509.Certificate
}

// blockingStatuses report compromise or revocation (FIDO MDS3 §3.1.4).
var blockingStatuses = []string{
	"USER_VERIFICATION_BYPASS",
	"ATTESTATION_KEY_COMPROMISE",
	"USER_KEY_REMOTE_COMPROMISE",
	"USER_KEY_PHYSICAL_COMPROMISE",
	"REVOKED",
}

// Number returns the BLOB's serial number. MDS3 §3.1.8 says to ignore a
// BLOB whose number is not higher than the one in use.
func (m *Metadata) Number() int { return m.number }

// NextUpdate returns the date by which a newer BLOB will be published.
func (m *Metadata) NextUpdate() time.Time { return m.nextUpdate }

// Lookup returns the metadata of the authenticator model with the given
// AAGUID. The AAGUID comes from the authenticator data, so a model can
// claim the AAGUID of another model whose attestation roots also trust it.
func (m *Metadata) Lookup(aaguid [16]byte) (MetadataEntry, bool) {
	e, ok := m.entries[aaguid]
	return e, ok
}

func (e MetadataEntry) blocked(chains [][]*x509.Certificate) bool {
	for _, r := range e.StatusReports {
		if !slices.Contains(blockingStatuses, r.Status) {
			continue
		}
		if r.Certificate == nil {
			return true
		}
		for _, chain := range chains {
			if slices.ContainsFunc(chain, r.Certificate.Equal) {
				return true
			}
		}
	}
	return false
}

// MetadataOption configures ParseMetadata and FetchMetadata.
type MetadataOption func(*metadataOptions)

type metadataOptions struct {
	crls []*x509.RevocationList
	now  func() time.Time
}

// WithCRLs supplies the certificate revocation lists for the BLOB's
// signing chain. FetchMetadata downloads them itself.
func WithCRLs(crls ...*x509.RevocationList) MetadataOption {
	return func(o *metadataOptions) { o.crls = append(o.crls, crls...) }
}

// WithMetadataClock overrides the time at which certificates and CRLs are
// checked.
func WithMetadataClock(now func() time.Time) MetadataOption {
	return func(o *metadataOptions) { o.now = now }
}

// ParseMetadata verifies and parses an MDS3 BLOB, a JWT whose x5c chain
// must lead to one of roots. As MDS3 §3.1.8 requires, every certificate in
// the chain but the root must be covered by a current CRL from WithCRLs,
// and none of those CRLs may revoke it. A BLOB past its nextUpdate is
// accepted: the caller fetches a newer one by NextUpdate and keeps it only
// if its Number is higher. Its errors do not wrap authent.ErrUnauthenticated.
func ParseMetadata(blob []byte, roots *x509.CertPool, opts ...MetadataOption) (*Metadata, error) {
	o := metadataOptions{now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}
	now := o.now()
	chains, payload, err := verifyMetadataJWS(blob, roots, now)
	if err != nil {
		return nil, err
	}
	if err := checkRevocation(chains, o.crls, now); err != nil {
		return nil, err
	}
	return parseMetadataPayload(payload)
}

// FetchMetadata downloads an MDS3 BLOB from url, such as MDS3URL, and the
// CRLs named by its signing chain with client, then verifies it as
// ParseMetadata does. It follows the client's redirects. The BLOB must
// come over https, so that a network attacker cannot replay an older
// signed BLOB. CRLs may come over http, as CAs publish them, because
// their signatures are verified.
func FetchMetadata(ctx context.Context, client *http.Client, url string, roots *x509.CertPool, opts ...MetadataOption) (*Metadata, error) {
	if client == nil {
		return nil, errors.New("webauthn: metadata: client is required")
	}
	blob, err := download(ctx, client, url, maxMetadataSize, true)
	if err != nil {
		return nil, err
	}
	o := metadataOptions{now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}
	chains, _, err := verifyMetadataJWS(blob, roots, o.now())
	if err != nil {
		return nil, err
	}
	var crls []*x509.RevocationList
	seen := map[string]bool{}
	for _, chain := range chains {
		for _, c := range chain[:len(chain)-1] {
			for _, u := range c.CRLDistributionPoints {
				if seen[u] || !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
					continue
				}
				seen[u] = true
				der, err := download(ctx, client, u, maxCRLSize, false)
				if err != nil {
					return nil, err
				}
				crl, err := x509.ParseRevocationList(der)
				if err != nil {
					return nil, fmt.Errorf("webauthn: metadata: CRL %s: %w", u, err)
				}
				crls = append(crls, crl)
			}
		}
	}
	return ParseMetadata(blob, roots, append(opts, WithCRLs(crls...))...)
}

func download(ctx context.Context, client *http.Client, url string, limit int64, httpsOnly bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("webauthn: metadata: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webauthn: metadata: %w", err)
	}
	defer resp.Body.Close()
	if httpsOnly && resp.Request.URL.Scheme != "https" {
		return nil, fmt.Errorf("webauthn: metadata: GET %s: not served over https", url)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webauthn: metadata: GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("webauthn: metadata: GET %s: %w", url, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("webauthn: metadata: GET %s: larger than %d bytes", url, limit)
	}
	return b, nil
}

func verifyMetadataJWS(blob []byte, roots *x509.CertPool, now time.Time) ([][]*x509.Certificate, []byte, error) {
	fail := func(format string, args ...any) ([][]*x509.Certificate, []byte, error) {
		return nil, nil, fmt.Errorf("webauthn: metadata: "+format, args...)
	}
	if roots == nil {
		return fail("roots are required")
	}
	parts := strings.Split(string(bytes.TrimSpace(blob)), ".")
	if len(parts) != 3 {
		return fail("not a JWS in compact serialization")
	}
	rawHeader, err1 := decodeB64(parts[0])
	payload, err2 := decodeB64(parts[1])
	sig, err3 := decodeB64(parts[2])
	if err := errors.Join(err1, err2, err3); err != nil {
		return fail("%v", err)
	}
	var h map[string]jsontext.Value
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return fail("header: %v", err)
	}
	var alg string
	var x5c []string
	var err error
	for k, v := range h {
		switch k {
		case "alg":
			err = json.Unmarshal(v, &alg)
		case "x5c":
			err = json.Unmarshal(v, &x5c)
		case "typ", "kid":
		default:
			return fail("unsupported header %q", k)
		}
		if err != nil {
			return fail("header %q: %v", k, err)
		}
	}
	if len(x5c) == 0 || len(x5c) > maxCertificates {
		return fail("x5c must hold 1 to %d certificates", maxCertificates)
	}
	certs := make([]*x509.Certificate, 0, len(x5c))
	for _, s := range x5c {
		der, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil {
			return fail("x5c: %v", err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fail("x5c: %v", err)
		}
		certs = append(certs, c)
	}
	if err := verifyJWSSignature(alg, certs[0].PublicKey, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return fail("%v", err)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fail("%v", err)
	}
	return chains, payload, nil
}

// verifyJWSSignature takes ES256 signatures as R || S, not DER (RFC 7518 §3.4).
func verifyJWSSignature(alg string, pub crypto.PublicKey, msg, sig []byte) error {
	h := sha256.Sum256(msg)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if alg == "RS256" && k.N.BitLen() >= MinRSABits && rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil {
			return nil
		}
	case *ecdsa.PublicKey:
		if alg == "ES256" && k.Curve == elliptic.P256() && len(sig) == 64 &&
			ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil
		}
	}
	return fmt.Errorf("invalid %s signature from a %T", alg, pub)
}

func checkRevocation(chains [][]*x509.Certificate, crls []*x509.RevocationList, now time.Time) error {
	var errs []error
	for _, chain := range chains {
		err := checkChainRevocation(chain, crls, now)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	return fmt.Errorf("webauthn: metadata: %w", errors.Join(errs...))
}

func checkChainRevocation(chain []*x509.Certificate, crls []*x509.RevocationList, now time.Time) error {
	for i, c := range chain[:len(chain)-1] {
		issuer := chain[i+1]
		covered := false
		for _, l := range crls {
			if !bytes.Equal(l.RawIssuer, c.RawIssuer) || now.Before(l.ThisUpdate) || !now.Before(l.NextUpdate) || l.CheckSignatureFrom(issuer) != nil {
				continue
			}
			covered = true
			for _, r := range l.RevokedCertificateEntries {
				if r.SerialNumber.Cmp(c.SerialNumber) == 0 {
					return fmt.Errorf("certificate %q is revoked", c.Subject)
				}
			}
		}
		if !covered {
			return fmt.Errorf("no current CRL for %q", c.Subject)
		}
	}
	return nil
}

type metadataPayload struct {
	No         *int   `json:"no"`
	NextUpdate string `json:"nextUpdate"`
	Entries    []struct {
		AAGUID            string         `json:"aaguid"`
		MetadataStatement jsontext.Value `json:"metadataStatement"`
		StatusReports     []struct {
			Status        string `json:"status"`
			EffectiveDate string `json:"effectiveDate"`
			Certificate   string `json:"certificate"`
		} `json:"statusReports"`
	} `json:"entries"`
}

// parseMetadataPayload skips entries without an AAGUID, which describe UAF
// or U2F authenticators.
func parseMetadataPayload(b []byte) (*Metadata, error) {
	fail := func(format string, args ...any) (*Metadata, error) {
		return nil, fmt.Errorf("webauthn: metadata: "+format, args...)
	}
	var p metadataPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return fail("%v", err)
	}
	next, err := time.Parse(time.DateOnly, p.NextUpdate)
	if err != nil || p.No == nil || *p.No < 0 {
		return fail("payload lacks a valid no or nextUpdate")
	}
	m := &Metadata{number: *p.No, nextUpdate: next, entries: map[[16]byte]MetadataEntry{}}
	for _, pe := range p.Entries {
		if pe.AAGUID == "" {
			continue
		}
		aaguid, ok := parseAAGUID(pe.AAGUID)
		if !ok {
			return fail("invalid AAGUID %q", pe.AAGUID)
		}
		if _, dup := m.entries[aaguid]; dup {
			return fail("duplicate AAGUID %q", pe.AAGUID)
		}
		var st struct {
			Description                 string   `json:"description"`
			AttestationRootCertificates []string `json:"attestationRootCertificates"`
		}
		// metadataStatement is optional; without it the model has no
		// attestation roots, so its attestations are not trusted.
		if pe.MetadataStatement != nil {
			if err := json.Unmarshal(pe.MetadataStatement, &st); err != nil {
				return fail("statement of %s: %v", pe.AAGUID, err)
			}
		}
		e := MetadataEntry{AAGUID: aaguid, Description: st.Description, Statement: pe.MetadataStatement}
		for _, s := range st.AttestationRootCertificates {
			if c := parseBase64Certificate(s); c != nil {
				e.AttestationRoots = append(e.AttestationRoots, c)
			}
		}
		for _, r := range pe.StatusReports {
			e.StatusReports = append(e.StatusReports, StatusReport{Status: r.Status, EffectiveDate: r.EffectiveDate, Certificate: parseBase64Certificate(r.Certificate)})
		}
		m.entries[aaguid] = e
	}
	return m, nil
}

func parseBase64Certificate(s string) *x509.Certificate {
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return c
}

func parseAAGUID(s string) ([16]byte, bool) {
	var a [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return a, false
	}
	n, err := hex.Decode(a[:], []byte(strings.ReplaceAll(s, "-", "")))
	return a, err == nil && n == 16
}
