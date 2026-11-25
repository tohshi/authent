package password

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func pwnedClient(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme != "https" || req.URL.Host != "api.pwnedpasswords.com" {
			t.Errorf("unexpected destination: %s", req.URL)
		}
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(server.URL, "http://")
		return http.DefaultTransport.RoundTrip(req)
	})}
}

func TestPwnedPasswordsChecker(t *testing.T) {
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
	const suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"breached", strings.Repeat("A", 35) + ":10\r\n" + suffix + ":3303003\r\n", true},
		{"not breached", strings.Repeat("A", 35) + ":10\n", false},
		{"padding", suffix + ":0\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := NewPwnedPasswordsChecker(pwnedClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/range/5BAA6" || r.Header.Get("Add-Padding") != "true" {
					t.Errorf("unexpected request: %s %s headers=%v", r.Method, r.URL, r.Header)
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			got, err := checker.Breached(context.Background(), "password")
			if err != nil || got != tc.want {
				t.Fatalf("Breached = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestPwnedPasswordsCheckerFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"HTTP error", 503, "unavailable"},
		{"empty", 200, ""},
		{"malformed", 200, "nonsense"},
		{"oversized", 200, strings.Repeat("x", maxPwnedReply+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := NewPwnedPasswordsChecker(pwnedClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			if clean, err := checker.Breached(context.Background(), "password"); err == nil || clean {
				t.Fatalf("Breached = %v, %v; want error", clean, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checker := NewPwnedPasswordsChecker(nil)
	if _, err := checker.Breached(ctx, "password"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request: %v", err)
	}
}
