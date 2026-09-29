package shellcode

import (
	"errors"
	"fmt"
	"strings"
)

// Shellcode encoders — transform raw bytes so a loader can decode them in
// place before jumping. The typical use: the C2 stager receives an encoded
// blob, decodes with a small decoder stub, then runs the shellcode. Different
// encodings defeat different filters.
//
//   xor       — single-byte XOR. null-free if the key avoids 0x00 in output.
//   rot13     — trivial byte rotation, defeats dumb signature scanners.
//   add       — additive byte rotation.
//   sub       — subtractive.
//   null_free — bytes equal to forbidden set are re-encoded via a small
//               two-byte escape. Result is guaranteed free of the forbidden
//               byte(s) at the cost of up to 2x size.
//   chunked   — split into N parts, each XOR'd with a different key.
//   base64    — wrap in a base64 blob for embedding in text channels.
//   uuid      — pack 16 bytes into a UUID string for HTTP smuggling.
//   ipv4      — pack 4 bytes into a dotted-quad for DNS / HTTP smuggling.

// Encoder transforms bytes and reports a decoder key.
type Encoder interface {
	Name() string
	Encode(in []byte) []byte
	// Key returns a short human-readable description of what the loader
	// needs to decode (e.g. the XOR key).
	Key() string
}

// --- XOR ---

type xorEncoder struct{ key byte }

// NewXOR returns a single-byte XOR encoder. If key is 0, picks the value
// that minimizes null bytes in the output — the encoder walks every byte
// and scores.
func NewXOR(key byte) Encoder {
	return &xorEncoder{key: key}
}

func (e *xorEncoder) Name() string { return "xor" }

func (e *xorEncoder) Encode(in []byte) []byte {
	k := e.key
	if k == 0 {
		k = pickXORKey(in)
	}
	out := make([]byte, len(in))
	for i, b := range in {
		out[i] = b ^ k
	}
	return out
}

func (e *xorEncoder) Key() string { return fmt.Sprintf("xor_key=0x%02x", e.key) }

// pickXORKey picks a byte whose XOR output has the fewest zeros.
func pickXORKey(in []byte) byte {
	best := byte(0xA5)
	bestScore := -1
	for k := 1; k < 256; k++ {
		score := 0
		for _, b := range in {
			if b^byte(k) == 0 {
				score--
			}
		}
		// prefer avoiding 0x00 and 0x0A/0x0D
		for _, b := range in {
			x := b ^ byte(k)
			if x == 0x00 || x == 0x0A || x == 0x0D {
				score--
			}
		}
		if score > bestScore {
			bestScore = score
			best = byte(k)
		}
	}
	return best
}

// --- ROT13 ---

type rotEncoder struct {
	n           int
	lettersOnly bool
}

// NewROT returns a byte rotation encoder (rotates every byte).
// For the classic letter-only ROT13 cipher, use NewROT13.
func NewROT(n int) Encoder { return &rotEncoder{n: n & 0xFF, lettersOnly: false} }

// NewROT13 returns the classic letter-only ROT13 cipher — only A-Z and
// a-z are rotated, everything else is passed through unchanged.
func NewROT13() Encoder { return &rotEncoder{n: 13, lettersOnly: true} }

func (e *rotEncoder) Name() string {
	if e.lettersOnly && e.n == 13 {
		return "rot13"
	}
	return fmt.Sprintf("rot%d", e.n)
}

func (e *rotEncoder) Encode(in []byte) []byte {
	out := make([]byte, len(in))
	if e.lettersOnly {
		for i, b := range in {
			switch {
			case b >= 'a' && b <= 'z':
				out[i] = byte('a' + (int(b-'a')+e.n)%26)
			case b >= 'A' && b <= 'Z':
				out[i] = byte('A' + (int(b-'A')+e.n)%26)
			default:
				out[i] = b
			}
		}
		return out
	}
	for i, b := range in {
		out[i] = byte((int(b) + e.n) & 0xFF)
	}
	return out
}

func (e *rotEncoder) Key() string {
	if e.lettersOnly && e.n == 13 {
		return "rot13-letters-only"
	}
	return fmt.Sprintf("rot_n=%d", e.n)
}

// --- null-free ---

type nullFreeEncoder struct{ forbidden map[byte]struct{} }

// NewNullFree returns an encoder that guarantees the output contains none
// of the forbidden bytes (default: 0x00, 0x0A, 0x0D). Escapes forbidden
// bytes as two bytes: 0x01 0xNN where NN = original ^ 0xFF.
//
// Loaders must implement the same escape rule.
func NewNullFree(forbidden ...byte) Encoder {
	if len(forbidden) == 0 {
		forbidden = []byte{0x00, 0x0A, 0x0D}
	}
	m := map[byte]struct{}{}
	for _, b := range forbidden {
		m[b] = struct{}{}
	}
	return &nullFreeEncoder{forbidden: m}
}

func (e *nullFreeEncoder) Name() string { return "null_free" }

func (e *nullFreeEncoder) Encode(in []byte) []byte {
	var out []byte
	for _, b := range in {
		if _, bad := e.forbidden[b]; bad {
			// escape: 0x01 then b^0xFF
			out = append(out, 0x01, b^0xFF)
		} else {
			out = append(out, b)
		}
	}
	return out
}

func (e *nullFreeEncoder) Key() string {
	var ks []string
	for b := range e.forbidden {
		ks = append(ks, fmt.Sprintf("0x%02x", b))
	}
	return "forbidden=[" + strings.Join(ks, ",") + "]"
}

// --- chunked XOR ---

type chunkedXOREncoder struct {
	chunk int
	keys  []byte
}

// NewChunkedXOR splits into chunks of `chunk` bytes and XORs each with a
// different key from keys. Rotates through the key ring.
func NewChunkedXOR(chunk int, keys []byte) Encoder {
	if chunk <= 0 {
		chunk = 16
	}
	if len(keys) == 0 {
		keys = []byte{0xA5}
	}
	return &chunkedXOREncoder{chunk: chunk, keys: keys}
}

func (e *chunkedXOREncoder) Name() string { return "chunked_xor" }

func (e *chunkedXOREncoder) Encode(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		k := e.keys[(i/e.chunk)%len(e.keys)]
		out[i] = b ^ k
	}
	return out
}

func (e *chunkedXOREncoder) Key() string {
	s := fmt.Sprintf("chunk=%d keys=[", e.chunk)
	for i, k := range e.keys {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf("0x%02x", k)
	}
	s += "]"
	return s
}

// --- base64 (text channel) ---

const b64Std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

type base64Encoder struct{}

// NewBase64 returns a base64 encoder.
func NewBase64() Encoder { return &base64Encoder{} }

func (e *base64Encoder) Name() string { return "base64" }

func (e *base64Encoder) Encode(in []byte) []byte {
	// standard base64 without an external dep
	var out []byte
	for i := 0; i < len(in); i += 3 {
		var b0, b1, b2 byte
		b0 = in[i]
		if i+1 < len(in) {
			b1 = in[i+1]
		}
		if i+2 < len(in) {
			b2 = in[i+2]
		}
		out = append(out, b64Std[b0>>2])
		out = append(out, b64Std[((b0&0x03)<<4)|(b1>>4)])
		if i+1 < len(in) {
			out = append(out, b64Std[((b1&0x0F)<<2)|(b2>>6)])
		} else {
			out = append(out, '=')
		}
		if i+2 < len(in) {
			out = append(out, b64Std[b2&0x3F])
		} else {
			out = append(out, '=')
		}
	}
	return out
}

func (e *base64Encoder) Key() string { return "base64-standard" }

// --- uuid (16 bytes per UUID) ---

// UUIDStrings packs the input into UUID-formatted strings. Every 16 bytes
// become one line in 8-4-4-4-12 form. Short tails are zero-padded. Useful
// when the only channel out is a field that accepts UUIDs.
func UUIDStrings(in []byte) []string {
	if len(in) == 0 {
		return nil
	}
	var out []string
	for i := 0; i < len(in); i += 16 {
		end := i + 16
		if end > len(in) {
			end = len(in)
		}
		chunk := make([]byte, 16)
		copy(chunk, in[i:end])
		u := fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			chunk[0], chunk[1], chunk[2], chunk[3],
			chunk[4], chunk[5],
			chunk[6], chunk[7],
			chunk[8], chunk[9],
			chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15])
		out = append(out, u)
	}
	return out
}

// --- ipv4 (4 bytes per address) ---

// IPv4Strings packs the input into dotted-quad strings. Every 4 bytes
// become one "10.x.y.z" address. Short tails are zero-padded. Useful for
// exfil through DNS queries where each query carries a fixed-size label.
func IPv4Strings(in []byte) []string {
	if len(in) == 0 {
		return nil
	}
	var out []string
	for i := 0; i < len(in); i += 4 {
		end := i + 4
		if end > len(in) {
			end = len(in)
		}
		chunk := make([]byte, 4)
		copy(chunk, in[i:end])
		out = append(out, fmt.Sprintf("10.%d.%d.%d", chunk[0], chunk[1], chunk[2]))
	}
	return out
}

// --- convenience ---

// EncoderByName returns an encoder by short name for the CLI.
func EncoderByName(name string, key uint8) (Encoder, error) {
	switch strings.ToLower(name) {
	case "xor":
		return NewXOR(key), nil
	case "rot13":
		return NewROT13(), nil
	case "rot":
		return NewROT(int(key)), nil
	case "null_free", "nullfree":
		return NewNullFree(), nil
	case "chunked_xor", "chunked":
		keys := []byte{key}
		if key == 0 {
			keys = []byte{0xA5, 0x5A, 0x3C, 0xC3}
		}
		return NewChunkedXOR(16, keys), nil
	case "base64", "b64":
		return NewBase64(), nil
	default:
		return nil, fmt.Errorf("shellcode: unknown encoder %q", name)
	}
}

// Encode runs an encoder and returns (encoded, keyDescription, error).
func Encode(name string, key uint8, in []byte) ([]byte, string, error) {
	e, err := EncoderByName(name, key)
	if err != nil {
		return nil, "", err
	}
	return e.Encode(in), e.Key(), nil
}

// Decode is the reference decoder for round-tripping inside this package
// and validating the encode step. Real loaders implement their own.
func Decode(e Encoder, in []byte) ([]byte, error) {
	switch enc := e.(type) {
	case *xorEncoder:
		k := enc.key
		if k == 0 {
			return nil, errors.New("shellcode: decode needs concrete key")
		}
		out := make([]byte, len(in))
		for i, b := range in {
			out[i] = b ^ k
		}
		return out, nil
	case *rotEncoder:
		out := make([]byte, len(in))
		for i, b := range in {
			out[i] = byte((int(b) - enc.n) & 0xFF)
		}
		return out, nil
	case *chunkedXOREncoder:
		out := make([]byte, len(in))
		for i, b := range in {
			k := enc.keys[(i/enc.chunk)%len(enc.keys)]
			out[i] = b ^ k
		}
		return out, nil
	}
	return nil, errors.New("shellcode: decode not implemented for that encoder")
}
