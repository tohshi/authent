package password

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type stubBreachChecker struct {
	called int
	seen   string
	result bool
	err    error
}

type stubBlocklist struct {
	called int
	seen   string
	err    error
}

func (s *stubBlocklist) Blocked(_ context.Context, password string) (bool, error) {
	s.called++
	s.seen = password
	return false, s.err
}

func (s *stubBreachChecker) Breached(_ context.Context, password string) (bool, error) {
	s.called++
	s.seen = password
	return s.result, s.err
}

func TestPolicyCheck(t *testing.T) {
	checker := &stubBreachChecker{}
	p, err := NewPolicy(3, 5, checker)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		password string
		want     error
	}{
		{"é猫", ErrTooShort},
		{"é猫a", nil},
		{"a b c", nil},
		{"123456", ErrTooLong},
		{string([]byte{0xff, 'a', 'b'}), ErrInvalidEncoding},
	} {
		before := checker.called
		err := p.Check(context.Background(), tc.password)
		if !errors.Is(err, tc.want) {
			t.Errorf("Check(%q) = %v, want %v", tc.password, err, tc.want)
		}
		if tc.want != nil && checker.called != before {
			t.Errorf("Check(%q) queried breach service", tc.password)
		}
	}
	if checker.seen != "a b c" {
		t.Fatalf("checker received %q", checker.seen)
	}
	checker.result = true
	if err := p.Check(context.Background(), "valid"); !errors.Is(err, ErrBreached) {
		t.Fatalf("breached password: %v", err)
	}
	checker.result = false
	checker.err = errors.New("service unavailable")
	if err := p.Check(context.Background(), "valid"); !errors.Is(err, checker.err) {
		t.Fatalf("breach service error: %v", err)
	}
}

func TestNewPolicyRejectsInvalidConfiguration(t *testing.T) {
	checker := &stubBreachChecker{}
	for _, tc := range []struct {
		min, max int
		checker  BreachChecker
	}{
		{0, 64, checker},
		{15, 14, checker},
		{15, 64, nil},
	} {
		if _, err := NewPolicy(tc.min, tc.max, tc.checker); err == nil {
			t.Errorf("NewPolicy(%d, %d, %v) succeeded", tc.min, tc.max, tc.checker)
		}
	}
	if DefaultMinLength != 15 || DefaultMaxLength < 64 {
		t.Fatal("default limits do not permit NIST-recommended lengths")
	}
	if _, err := NewPolicy(DefaultMinLength, DefaultMaxLength, checker); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPolicy(3, 5, checker, WithBlocklist(nil)); err == nil {
		t.Fatal("NewPolicy accepted a nil blocklist")
	}
}

func TestPolicyBlocklistUsesWholeNormalizedPassword(t *testing.T) {
	blocklist, err := NewStaticBlocklist("café")
	if err != nil {
		t.Fatal(err)
	}
	checker := &stubBreachChecker{}
	p, err := NewPolicy(1, 64, checker, WithBlocklist(blocklist))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Check(context.Background(), "cafe\u0301"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("normalized blocked password: %v", err)
	}
	if checker.called != 0 {
		t.Fatal("blocked password queried breach service")
	}
	if err := p.Check(context.Background(), "a café in a phrase"); err != nil {
		t.Fatalf("substring falsely blocked: %v", err)
	}
	if _, err := NewStaticBlocklist(string([]byte{0xff})); err == nil {
		t.Fatal("invalid UTF-8 blocklist entry accepted")
	}

	failing := &stubBlocklist{err: errors.New("blocklist unavailable")}
	p, err = NewPolicy(1, 64, checker, WithBlocklist(failing))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Check(context.Background(), "cafe\u0301"); !errors.Is(err, failing.err) {
		t.Fatalf("blocklist error: %v", err)
	}
	if failing.seen != "café" {
		t.Fatalf("blocklist received %q, want NFC", failing.seen)
	}
}

func TestPolicyHashNormalizesAndTags(t *testing.T) {
	h := newTestHasher(t)
	checker := &stubBreachChecker{}
	p, err := NewPolicy(1, 64, checker)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := p.Hash(context.Background(), h, "cafe\u0301")
	if err != nil {
		t.Fatal(err)
	}
	if checker.seen != "café" || !strings.Contains(encoded, ",norm=nfc$") {
		t.Fatalf("normalization missing: checker saw %q; hash %q", checker.seen, encoded)
	}
	for _, submitted := range []string{"café", "cafe\u0301"} {
		if err := h.Verify(submitted, encoded); err != nil {
			t.Fatalf("Verify(%q) = %v", submitted, err)
		}
	}
	if err := h.Verify("cafe", encoded); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := h.Verify(string([]byte{0xff}), encoded); !errors.Is(err, ErrMismatch) {
		t.Fatalf("invalid UTF-8 matched: %v", err)
	}
	legacy, err := h.Hash("cafe\u0301")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify("café", legacy); !errors.Is(err, ErrMismatch) {
		t.Fatalf("legacy hash unexpectedly normalized: %v", err)
	}
	if err := h.Verify("cafe\u0301", legacy); err != nil {
		t.Fatalf("legacy hash no longer verifies: %v", err)
	}
}

func TestPolicyLengthCountsNormalizedCodePoints(t *testing.T) {
	p, err := NewPolicy(2, 2, &stubBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Check(context.Background(), "e\u0301"); !errors.Is(err, ErrTooShort) {
		t.Fatalf("decomposed character counted twice: %v", err)
	}
	if err := p.Check(context.Background(), "e\u0301x"); err != nil {
		t.Fatalf("normalized two-character password rejected: %v", err)
	}
}
