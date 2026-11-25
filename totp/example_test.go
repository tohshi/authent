package totp_test

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/tohshi/authent/totp"
)

// memStore is a minimal in-memory totp.Store.
type memStore struct {
	mu    sync.Mutex
	creds map[string]totp.Credential
}

func (s *memStore) LookupCredential(_ context.Context, subject string) (totp.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[subject]
	if !ok {
		return totp.Credential{}, totp.ErrNotEnrolled
	}
	return c, nil
}

func (s *memStore) AdvanceCounter(_ context.Context, subject string, counter uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.creds[subject]
	if counter <= c.LastCounter {
		return totp.ErrReplay
	}
	c.LastCounter = counter
	s.creds[subject] = c
	return nil
}

// Enroll a user, then verify a code as the second factor of a login.
func Example() {
	ctx := context.Background()
	store := &memStore{creds: map[string]totp.Credential{}}

	// Enrollment: show uri as a QR code and ask for the first code.
	key, _ := totp.GenerateKey()
	uri, _ := key.URI("Example", "alice@example.com")
	_ = uri
	first, _ := key.Code(time.Now()) // typed by the user
	counter, err := key.Verify(first, time.Now(), totp.DefaultSkew)
	if err != nil {
		panic(err)
	}
	store.creds["u1"] = totp.Credential{Subject: "u1", Key: key, LastCounter: counter}

	// Login, after the password was checked. The enrollment code cannot be
	// reused, so use the code of the next time step.
	auth, _ := totp.NewAuthenticator(store)
	next, _ := key.Code(time.Now().Add(key.Period))
	p, err := auth.Authenticate(ctx, "u1", next)
	fmt.Println(p.Subject, p.Method, err)
	_, err = auth.Authenticate(ctx, "u1", next)
	fmt.Println(err)
	// Output:
	// u1 totp <nil>
	// totp: invalid code: authent: unauthenticated: already used
}
