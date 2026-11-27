package webauthn

import (
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
)

type pySamples struct {
	Samples []struct {
		Format     string `json:"format"`
		Name       string `json:"name"`
		Credential string `json:"credential"`
		Challenge  string `json:"challenge"`
		RPID       string `json:"rp_id"`
		Origin     string `json:"expected_origin"`
		Time       string `json:"time"`
	} `json:"samples"`
	Roots map[string]string `json:"roots"`
}

func TestRealAttestationSamples(t *testing.T) {
	data, err := os.ReadFile("testdata/py_webauthn_samples.json")
	if err != nil {
		t.Fatal(err)
	}
	var ps pySamples
	if err := json.Unmarshal(data, &ps); err != nil {
		t.Fatal(err)
	}
	roots := map[string]*x509.CertPool{"android-key": x509.NewCertPool(), "apple": x509.NewCertPool()}
	for name, p := range ps.Roots {
		block, _ := pem.Decode([]byte(p))
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		switch {
		case strings.HasPrefix(name, "google_hardware_attestation_root"):
			roots["android-key"].AddCert(c)
		case strings.HasPrefix(name, "apple"):
			roots["apple"].AddCert(c)
		}
	}
	want := map[string]AttestationType{"tpm": AttestationAttCA, "android-key": AttestationBasic, "apple": AttestationAnonCA}
	if len(ps.Samples) != 7 {
		t.Fatalf("got %d samples, want 7", len(ps.Samples))
	}
	for _, s := range ps.Samples {
		t.Run(s.Name, func(t *testing.T) {
			now := testNow
			if s.Time != "" {
				now, _ = time.Parse(time.RFC3339, s.Time)
			}
			cfg := Config{RPID: s.RPID, Origins: []string{s.Origin}, Algorithms: allAlgorithms, Attestation: ConveyanceDirect}
			// The TPM vendors' roots are not part of the samples, so TPM
			// statements are verified but not trusted.
			cfg.AttestationRoots = roots[s.Format]
			rp, err := New(cfg, newMemStore(), WithClock(func() time.Time { return now }))
			if err != nil {
				t.Fatal(err)
			}
			value, err := decodeB64(s.Challenge)
			if err != nil {
				t.Fatal(err)
			}
			ch := Challenge{Ceremony: ceremonyCreate, Value: value, ExpiresAt: now.Add(time.Minute), Subject: "u-1", UserHandle: []byte("h")}
			reg, err := rp.FinishRegistration(context.Background(), ch, []byte(s.Credential))
			if err != nil {
				t.Fatalf("FinishRegistration = %v", err)
			}
			if c := reg.Credential; c.AttestationFormat != s.Format || c.AttestationType != want[s.Format] {
				t.Fatalf("attestation = %s/%s", c.AttestationFormat, c.AttestationType)
			}
		})
	}
}
