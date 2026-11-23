package swtele

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Opt is a value a device may not report. The zero value is absent.
// Absent values encode as JSON null.
type Opt[T any] struct {
	V  T
	OK bool
}

// Some returns a present value.
func Some[T any](v T) Opt[T] { return Opt[T]{V: v, OK: true} }

// Get returns the value and whether it is present.
func (o Opt[T]) Get() (T, bool) { return o.V, o.OK }

// Or returns the value, or def when absent.
func (o Opt[T]) Or(def T) T {
	if o.OK {
		return o.V
	}
	return def
}

// IsZero reports absence, for the omitzero JSON option.
func (o Opt[T]) IsZero() bool { return !o.OK }

// MarshalJSON encodes the value, or null when absent.
func (o Opt[T]) MarshalJSON() ([]byte, error) {
	if !o.OK {
		return []byte("null"), nil
	}
	b, err := json.Marshal(o.V)
	if err != nil {
		return nil, fmt.Errorf("swtele: encode optional value: %w", err)
	}
	return b, nil
}

// UnmarshalJSON decodes a value; null is absent.
func (o *Opt[T]) UnmarshalJSON(b []byte) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		*o = Opt[T]{}
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("swtele: decode optional value: %w", err)
	}
	*o = Some(v)
	return nil
}

// MAC is a 48-bit hardware address. It is comparable and usable as a map
// key; the zero value is "no address".
type MAC [6]byte

// ErrMAC reports text that is not a MAC address.
var ErrMAC = errors.New("swtele: invalid MAC address")

// ParseMAC accepts the spellings device CLIs print: xxxx-xxxx-xxxx
// (Comware), xxxx.xxxx.xxxx (Cisco), xx:xx:xx:xx:xx:xx and xx-xx-xx-xx-xx-xx,
// in either case.
func ParseMAC(s string) (MAC, error) {
	var m MAC
	hexDigits := strings.Map(func(r rune) rune {
		switch r {
		case '-', '.', ':':
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(hexDigits) != 12 {
		return m, fmt.Errorf("%w: %q", ErrMAC, s)
	}
	if _, err := hex.Decode(m[:], []byte(hexDigits)); err != nil {
		return MAC{}, fmt.Errorf("%w: %q", ErrMAC, s)
	}
	return m, nil
}

// IsZero reports the zero address.
func (m MAC) IsZero() bool { return m == MAC{} }

// String formats the address as lowercase xx:xx:xx:xx:xx:xx, or "" for
// the zero address.
func (m MAC) String() string {
	if m.IsZero() {
		return ""
	}
	var b strings.Builder
	for i, octet := range m {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02x", octet)
	}
	return b.String()
}

// OUI returns the organizationally unique identifier, the first three
// octets, as "xx:xx:xx".
func (m MAC) OUI() string { return m.String()[:8] }

// Multicast reports a group address (I/G bit set).
func (m MAC) Multicast() bool { return m[0]&1 == 1 }

// MarshalText encodes the canonical form.
func (m MAC) MarshalText() ([]byte, error) { return []byte(m.String()), nil }

// UnmarshalText decodes any accepted spelling; empty is the zero address.
func (m *MAC) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*m = MAC{}
		return nil
	}
	v, err := ParseMAC(string(b))
	if err != nil {
		return err
	}
	*m = v
	return nil
}
