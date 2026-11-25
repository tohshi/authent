package session

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
)

// Key names a session value of type T. Values are stored as JSON, so T
// must round-trip through encoding/json/v2. Declare one Key per value:
//
//	var cartKey = session.Key[Cart]("cart")
type Key[T any] string

// Get returns the value under k. ok is false if s has no such value. A
// value that does not decode into T, for example one stored by an older
// version of the application, is an error.
func (k Key[T]) Get(s *Session) (v T, ok bool, err error) {
	raw, ok := s.values[string(k)]
	if !ok {
		return v, false, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, true, fmt.Errorf("session: decoding value %q: %w", string(k), err)
	}
	return v, true, nil
}

// Set stores v under k. Call Manager.Save to persist it.
func (k Key[T]) Set(s *Session, v T) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("session: encoding value %q: %w", string(k), err)
	}
	if s.values == nil {
		s.values = map[string]jsontext.Value{}
	}
	s.values[string(k)] = raw
	return nil
}

// Delete removes the value under k. Call Manager.Save to persist it.
func (k Key[T]) Delete(s *Session) {
	delete(s.values, string(k))
}
