package cryptogo

import "encoding/binary"

// RIPEMD-160 in pure Go. Go's stdlib does not ship this hash; Bitcoin's
// P2PKH uses RIPEMD160(SHA256(pubkey)) so we need it for correct addresses.

var ripemdR1 = [80]uint8{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}

var ripemdR2 = [80]uint8{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}

var ripemdS1 = [80]uint8{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}

var ripemdS2 = [80]uint8{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}

func ripemdF(j int, x, y, z uint32) uint32 {
	switch {
	case j < 16:
		return x ^ y ^ z
	case j < 32:
		return (x & y) | (^x & z)
	case j < 48:
		return (x | ^y) ^ z
	case j < 64:
		return (x & z) | (y & ^z)
	default:
		return x ^ (y | ^z)
	}
}

func ripemdK1(j int) uint32 {
	switch {
	case j < 16:
		return 0
	case j < 32:
		return 0x5A827999
	case j < 48:
		return 0x6ED9EBA1
	case j < 64:
		return 0x8F1BBCDC
	default:
		return 0xA953FD4E
	}
}

func ripemdK2(j int) uint32 {
	switch {
	case j < 16:
		return 0x50A28BE6
	case j < 32:
		return 0x5C4DD124
	case j < 48:
		return 0x6D703EF3
	case j < 64:
		return 0x7A6D76E9
	default:
		return 0
	}
}

func rol(x uint32, n uint8) uint32 { return (x << n) | (x >> (32 - n)) }

// RIPEMD160 computes the 20-byte RIPEMD-160 digest of msg.
func RIPEMD160(msg []byte) []byte {
	// padding — append 0x80, zeros, then 8-byte length LE
	l := uint64(len(msg)) * 8
	padded := append([]byte(nil), msg...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	var lbytes [8]byte
	binary.LittleEndian.PutUint64(lbytes[:], l)
	padded = append(padded, lbytes[:]...)

	h0 := uint32(0x67452301)
	h1 := uint32(0xEFCDAB89)
	h2 := uint32(0x98BADCFE)
	h3 := uint32(0x10325476)
	h4 := uint32(0xC3D2E1F0)

	for off := 0; off < len(padded); off += 64 {
		var X [16]uint32
		for i := 0; i < 16; i++ {
			X[i] = binary.LittleEndian.Uint32(padded[off+i*4 : off+i*4+4])
		}
		al, bl, cl, dl, el := h0, h1, h2, h3, h4
		ar, br, cr, dr, er := h0, h1, h2, h3, h4

		for j := 0; j < 80; j++ {
			// left round
			t := rol(al+ripemdF(j, bl, cl, dl)+X[ripemdR1[j]]+ripemdK1(j), ripemdS1[j]) + el
			al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
			// right round
			t2 := rol(ar+ripemdF(79-j, br, cr, dr)+X[ripemdR2[j]]+ripemdK2(j), ripemdS2[j]) + er
			ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t2
		}
		t := h1 + cl + dr
		h1 = h2 + dl + er
		h2 = h3 + el + ar
		h3 = h4 + al + br
		h4 = h0 + bl + cr
		h0 = t
	}
	out := make([]byte, 20)
	binary.LittleEndian.PutUint32(out[0:4], h0)
	binary.LittleEndian.PutUint32(out[4:8], h1)
	binary.LittleEndian.PutUint32(out[8:12], h2)
	binary.LittleEndian.PutUint32(out[12:16], h3)
	binary.LittleEndian.PutUint32(out[16:20], h4)
	return out
}
