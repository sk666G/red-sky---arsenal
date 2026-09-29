package cryptogo

import "encoding/binary"

// Keccak-256 (the pre-SHA3 variant used by Ethereum) in pure Go.
// Go's crypto/sha3 does not expose legacy keccak — the padding differs
// (0x01 vs 0x06). This is a compact implementation good enough for
// address derivation.
//
// State: 25 lanes of 64 bits. Rate 1088 bits = 136 bytes. Capacity 512.

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var keccakRot = [24]uint8{
	1, 3, 6, 10, 15, 21, 28, 36,
	45, 55, 2, 14, 27, 41, 56, 8,
	25, 43, 62, 18, 39, 61, 20, 44,
}

var keccakPi = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16,
	8, 21, 24, 4, 15, 23, 19, 13,
	12, 2, 20, 14, 22, 9, 6, 1,
}

func keccakF1600(st *[25]uint64) {
	var bc [5]uint64
	for round := 0; round < 24; round++ {
		// theta
		for i := 0; i < 5; i++ {
			bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20]
		}
		for i := 0; i < 5; i++ {
			t := bc[(i+4)%5] ^ rol64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				st[j+i] ^= t
			}
		}
		// rho + pi
		t := st[1]
		for i := 0; i < 24; i++ {
			j := keccakPi[i]
			bc[0] = st[j]
			st[j] = rol64(t, keccakRot[i])
			t = bc[0]
		}
		// chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				st[j+i] ^= (^bc[(i+1)%5]) & bc[(i+2)%5]
			}
		}
		// iota
		st[0] ^= keccakRC[round]
	}
}

func rol64(x uint64, n uint8) uint64 {
	if n == 0 {
		return x
	}
	return (x << n) | (x >> (64 - n))
}

// Keccak256 computes the 32-byte keccak-256 digest.
func Keccak256(data []byte) []byte {
	const rate = 136
	var st [25]uint64

	// absorb
	// pad10*1 with 0x01 domain byte (keccak, not sha3)
	padded := append([]byte(nil), data...)
	padded = append(padded, 0x01)
	for len(padded)%rate != 0 {
		padded = append(padded, 0)
	}
	padded[len(padded)-1] |= 0x80

	for off := 0; off < len(padded); off += rate {
		for i := 0; i < rate/8; i++ {
			st[i] ^= binary.LittleEndian.Uint64(padded[off+i*8 : off+i*8+8])
		}
		keccakF1600(&st)
	}
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:i*8+8], st[i])
	}
	return out
}
