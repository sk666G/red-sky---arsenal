package evade

// Compile-time string obfuscation.
//
// Goal: sensitive strings (DLL names, API names, ETW provider names) should
// not appear as plaintext in the compiled binary. A simple XOR-per-byte scheme
// is enough to defeat naive `strings binary | grep AmsiScanBuffer` scanning.
// This is not cryptographic strength; it's a scanning-speed bump. Anything
// that actually decodes the binary in a sandbox will still see the logic.
//
// Usage:
//   var key byte = 0xA7
//   var encrypted = []byte{...}  // produce with EncodeString("plaintext", key)
//   s := DecodeString(encrypted, key)

// EncodeString returns plaintext XOR'd with key, at the caller's compile time.
// Intended to be run at development time to produce byte slices to paste.
func EncodeString(s string, key byte) []byte {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = s[i] ^ key
	}
	return out
}

// DecodeString reverses EncodeString. Called at runtime.
func DecodeString(b []byte, key byte) string {
	out := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		out[i] = b[i] ^ key
	}
	return string(out)
}

// XorInPlace mutates b by XOR'ing every byte with key. Used when we want to
// decrypt a buffer, use it, then re-encrypt.
func XorInPlace(b []byte, key byte) {
	for i := range b {
		b[i] ^= key
	}
}
