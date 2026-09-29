package cryptogo

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// The known brainwallet reference: "correct horse battery staple" →
// SHA256(passphrase) mod n. Verified earlier tonight against the Python
// side; pinned here as a regression guard.
const (
	referencePassphrase = "correct horse battery staple"
	referencePrivHex    = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
	referenceP2PKH      = "1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8"
	referenceP2WPKH     = "bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4"
)

// TestBrainwalletReferencePriv pins the private key derived from the
// reference passphrase.
func TestBrainwalletReferencePriv(t *testing.T) {
	priv := BrainwalletPriv(referencePassphrase)
	got := PrivHex(priv)
	if got != referencePrivHex {
		t.Fatalf("brainwallet priv mismatch:\n  got  %s\n  want %s", got, referencePrivHex)
	}
}

// TestBrainwalletP2PKH pins the Bitcoin P2PKH address. This is the
// regression guard against RIPEMD160, base58check, and secp256k1 — if any
// one of them drifts, the address changes.
func TestBrainwalletP2PKH(t *testing.T) {
	priv := BrainwalletPriv(referencePassphrase)
	p2pkh, _, _, err := Addresses(priv)
	if err != nil {
		t.Fatal(err)
	}
	if p2pkh != referenceP2PKH {
		t.Fatalf("p2pkh mismatch:\n  got  %s\n  want %s", p2pkh, referenceP2PKH)
	}
}

// TestBrainwalletP2WPKH pins the bech32 P2WPKH address.
func TestBrainwalletP2WPKH(t *testing.T) {
	priv := BrainwalletPriv(referencePassphrase)
	_, p2wpkh, _, err := Addresses(priv)
	if err != nil {
		t.Fatal(err)
	}
	if p2wpkh != referenceP2WPKH {
		t.Fatalf("p2wpkh mismatch:\n  got  %s\n  want %s", p2wpkh, referenceP2WPKH)
	}
}

// TestRIPEMD160Empty pins the RIPEMD-160 of the empty string.
// Reference: 9c1185a5c5e9fc54612808977ee8f548b2258d31
func TestRIPEMD160Empty(t *testing.T) {
	got := hex.EncodeToString(RIPEMD160(nil))
	want := "9c1185a5c5e9fc54612808977ee8f548b2258d31"
	if got != want {
		t.Fatalf("ripemd160(empty) mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// TestRIPEMD160Abc pins RIPEMD-160("abc").
// Reference: 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
func TestRIPEMD160Abc(t *testing.T) {
	got := hex.EncodeToString(RIPEMD160([]byte("abc")))
	want := "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
	if got != want {
		t.Fatalf("ripemd160(abc) mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// TestKeccak256Empty pins keccak-256 of the empty string.
// Reference: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
func TestKeccak256Empty(t *testing.T) {
	got := hex.EncodeToString(Keccak256(nil))
	want := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got != want {
		t.Fatalf("keccak256(empty) mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// TestKeccak256HelloWorld pins keccak-256 of "hello world".
// Reference: 47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad
func TestKeccak256HelloWorld(t *testing.T) {
	got := hex.EncodeToString(Keccak256([]byte("hello world")))
	want := "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
	if got != want {
		t.Fatalf("keccak256(hello world) mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// TestPubkeyCompression checks that compressed and uncompressed pubkeys
// share the same x-coordinate and the compressed prefix matches y parity.
func TestPubkeyCompression(t *testing.T) {
	priv := big.NewInt(1) // generator point
	compressed, err := PubkeyFromPriv(priv, true)
	if err != nil {
		t.Fatal(err)
	}
	uncompressed, err := PubkeyFromPriv(priv, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(compressed) != 33 {
		t.Fatalf("compressed length %d, want 33", len(compressed))
	}
	if len(uncompressed) != 65 {
		t.Fatalf("uncompressed length %d, want 65", len(uncompressed))
	}
	if uncompressed[0] != 0x04 {
		t.Fatalf("uncompressed prefix 0x%02x, want 0x04", uncompressed[0])
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		t.Fatalf("compressed prefix wrong: 0x%02x", compressed[0])
	}
	// x coordinates should match
	for i := 0; i < 32; i++ {
		if compressed[1+i] != uncompressed[1+i] {
			t.Fatalf("x coordinate mismatch at byte %d", i)
		}
	}
	// generator y is even (SECP_Gy ends in 0x...B8 = even), so prefix
	// should be 0x02
	if compressed[0] != 0x02 {
		t.Fatalf("generator compressed prefix 0x%02x, want 0x02", compressed[0])
	}
}

// TestPubkeyRejectsZeroKey confirms the range check fires.
func TestPubkeyRejectsZeroKey(t *testing.T) {
	_, err := PubkeyFromPriv(big.NewInt(0), true)
	if err == nil {
		t.Fatalf("expected error for priv=0")
	}
}

// TestPubkeyRejectsOutOfRange checks that priv >= n is rejected.
func TestPubkeyRejectsOutOfRange(t *testing.T) {
	_, err := PubkeyFromPriv(secpN, true)
	if err == nil {
		t.Fatalf("expected error for priv=n")
	}
}

// TestRandomPrivInRange generates a few random keys and confirms they are
// all in the valid range.
func TestRandomPrivInRange(t *testing.T) {
	for i := 0; i < 8; i++ {
		priv, err := RandomPriv()
		if err != nil {
			t.Fatal(err)
		}
		if priv.Sign() <= 0 || priv.Cmp(secpN) >= 0 {
			t.Fatalf("random priv out of range: %s", priv.String())
		}
	}
}

// TestPrivHexPadding confirms that a small private key is zero-padded to
// 64 hex chars.
func TestPrivHexPadding(t *testing.T) {
	got := PrivHex(big.NewInt(1))
	if len(got) != 64 {
		t.Fatalf("priv hex length %d, want 64", len(got))
	}
	if got != "0000000000000000000000000000000000000000000000000000000000000001" {
		t.Fatalf("priv hex padding wrong: %s", got)
	}
}

// TestBase58EncodeKnown pins a base58 check on a known input. Round-trip
// requires a decoder, which wallet.go doesn't ship — this is the encode
// side only.
//
// base58check(0x00, RIPEMD160(SHA256(compressed generator pubkey))) should
// produce an address starting with "1". A known-answer test on the encoder
// itself: base58encode(0x00000000000000000000) = "1111111111" (ten zeros
// become ten leading '1's plus nothing else — leading zeros map to '1').
func TestBase58EncodeLeadingZeros(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00}
	got := base58Encode(data)
	// three zero bytes → three leading '1's
	if !strings.HasPrefix(got, "111") {
		t.Fatalf("base58 leading zeros not preserved: %q", got)
	}
}

// TestBech32CharsetLimits confirms the encoder only emits charset chars
// after the hrp + '1'.
func TestBech32CharsetLimits(t *testing.T) {
	priv := BrainwalletPriv("test")
	_, p2wpkh, _, err := Addresses(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p2wpkh, "bc1") {
		t.Fatalf("p2wpkh should start with bc1: %s", p2wpkh)
	}
	body := p2wpkh[3:]
	for _, c := range body {
		if !strings.ContainsRune(bech32Charset, c) {
			t.Fatalf("non-charset char %q in bech32 body", c)
		}
	}
}
