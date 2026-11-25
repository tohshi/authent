package webauthn

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// This file implements the subset of CBOR (RFC 8949) that WebAuthn uses:
// integers, byte and text strings, arrays, maps and the simple values
// false, true and null. Tags, floating-point numbers and indefinite-length
// items are rejected; CTAP2 canonical encoding does not use them.
//
// Decoded values are int64, []byte, string, []any, cborMap, bool or nil.

// cborMap is a decoded map. Keys are int64 or string.
type cborMap map[any]any

const (
	cborMaxDepth = 16
	// cborMaxItems bounds the number of elements in one array or map, so
	// that a short input cannot make the decoder allocate a lot of memory.
	cborMaxItems = 1024
)

var errCBOR = errors.New("invalid CBOR")

// cborDecode decodes the first item in data and returns the remaining
// bytes.
func cborDecode(data []byte) (any, []byte, error) {
	d := cborDecoder{data: data}
	v, err := d.item(0)
	if err != nil {
		return nil, nil, err
	}
	return v, d.data[d.off:], nil
}

// cborDecodeAll decodes data, which must hold exactly one item.
func cborDecodeAll(data []byte) (any, error) {
	v, rest, err := cborDecode(data)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing bytes", errCBOR)
	}
	return v, nil
}

type cborDecoder struct {
	data []byte
	off  int
}

func (d *cborDecoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.data)-d.off) {
		return nil, fmt.Errorf("%w: unexpected end of input", errCBOR)
	}
	b := d.data[d.off : d.off+int(n)]
	d.off += int(n)
	return b, nil
}

// head reads an initial byte and its argument.
func (d *cborDecoder) head() (major byte, arg uint64, err error) {
	b, err := d.take(1)
	if err != nil {
		return 0, 0, err
	}
	major, info := b[0]>>5, b[0]&0x1f
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info <= 27:
		ext, err := d.take(1 << (info - 24))
		if err != nil {
			return 0, 0, err
		}
		var v uint64
		for _, c := range ext {
			v = v<<8 | uint64(c)
		}
		return major, v, nil
	}
	// 28-30 are reserved and 31 is indefinite length.
	return 0, 0, fmt.Errorf("%w: unsupported additional information %d", errCBOR, info)
}

func (d *cborDecoder) item(depth int) (any, error) {
	if depth > cborMaxDepth {
		return nil, fmt.Errorf("%w: nested too deeply", errCBOR)
	}
	major, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0: // unsigned integer
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: integer out of range", errCBOR)
		}
		return int64(arg), nil
	case 1: // negative integer -1-arg
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: integer out of range", errCBOR)
		}
		return -1 - int64(arg), nil
	case 2: // byte string
		b, err := d.take(arg)
		if err != nil {
			return nil, err
		}
		return bytes.Clone(b), nil
	case 3: // text string
		b, err := d.take(arg)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, fmt.Errorf("%w: invalid UTF-8", errCBOR)
		}
		return string(b), nil
	case 4: // array
		if arg > cborMaxItems {
			return nil, fmt.Errorf("%w: array too long", errCBOR)
		}
		a := make([]any, 0, arg)
		for range arg {
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		return a, nil
	case 5: // map
		if arg > cborMaxItems {
			return nil, fmt.Errorf("%w: map too long", errCBOR)
		}
		m := make(cborMap, arg)
		for range arg {
			k, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, fmt.Errorf("%w: unsupported map key type %T", errCBOR, k)
			}
			if _, dup := m[k]; dup {
				return nil, fmt.Errorf("%w: duplicate map key %v", errCBOR, k)
			}
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		return m, nil
	case 7: // simple values and floats
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, fmt.Errorf("%w: unsupported simple value or float", errCBOR)
	}
	// Major type 6 (tags).
	return nil, fmt.Errorf("%w: tags are not supported", errCBOR)
}

// Typed accessors. Each returns false if the key is missing or the value
// has a different type.

func (m cborMap) bytes(k any) ([]byte, bool) {
	v, ok := m[k].([]byte)
	return v, ok
}

func (m cborMap) int(k any) (int64, bool) {
	v, ok := m[k].(int64)
	return v, ok
}

func (m cborMap) text(k any) (string, bool) {
	v, ok := m[k].(string)
	return v, ok
}
