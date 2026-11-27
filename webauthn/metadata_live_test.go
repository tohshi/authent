package webauthn

import (
	"context"
	"crypto/x509"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestLiveMDS3(t *testing.T) {
	if os.Getenv("AUTHENT_MDS3_LIVE") != "1" {
		t.Skip("set AUTHENT_MDS3_LIVE=1 to fetch the live MDS3 BLOB")
	}
	pem, err := os.ReadFile("testdata/globalsign-root-r3.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("no root certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	md, err := FetchMetadata(ctx, http.DefaultClient, MDS3URL, roots)
	if err != nil {
		t.Fatal(err)
	}
	withRoots, blocked := 0, 0
	for _, e := range md.entries {
		if len(e.AttestationRoots) > 0 {
			withRoots++
		}
		if e.blocked(nil) {
			blocked++
		}
	}
	t.Logf("BLOB no %d, next update %s: %d AAGUID entries, %d with attestation roots, %d with an unscoped compromise or revocation report",
		md.Number(), md.NextUpdate().Format(time.DateOnly), len(md.entries), withRoots, blocked)
	if len(md.entries) == 0 || withRoots == 0 {
		t.Fatal("no usable entries")
	}
}
