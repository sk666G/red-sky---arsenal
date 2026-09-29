package cryptogo

import "encoding/binary"

// MD4 in pure Go. Needed for NTLM (MD4(UTF-16LE(password))). Go's stdlib
// dropped MD4 years ago — this is a compact correct implementation.

func md4F(x, y, z uint32) uint32      { return (x & y) | (^x & z) }
func md4G(x, y, z uint32) uint32      { return (x & y) | (x & z) | (y & z) }
func md4H(x, y, z uint32) uint32      { return x ^ y ^ z }
func md4Rol(x uint32, n uint8) uint32 { return (x << n) | (x >> (32 - n)) }

// MD4 returns the 16-byte MD4 digest.
func MD4(msg []byte) []byte {
	l := uint64(len(msg)) * 8
	padded := append([]byte(nil), msg...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	var lbytes [8]byte
	binary.LittleEndian.PutUint64(lbytes[:], l)
	padded = append(padded, lbytes[:]...)

	a0 := uint32(0x67452301)
	b0 := uint32(0xEFCDAB89)
	c0 := uint32(0x98BADCFE)
	d0 := uint32(0x10325476)

	for off := 0; off < len(padded); off += 64 {
		var X [16]uint32
		for i := 0; i < 16; i++ {
			X[i] = binary.LittleEndian.Uint32(padded[off+i*4 : off+i*4+4])
		}
		a, b, c, d := a0, b0, c0, d0

		// round 1
		s1 := []uint8{3, 7, 11, 19}
		for i := 0; i < 16; i++ {
			switch i % 4 {
			case 0:
				a = md4Rol(a+md4F(b, c, d)+X[i], s1[0])
			case 1:
				d = md4Rol(d+md4F(a, b, c)+X[i], s1[1])
			case 2:
				c = md4Rol(c+md4F(d, a, b)+X[i], s1[2])
			case 3:
				b = md4Rol(b+md4F(c, d, a)+X[i], s1[3])
			}
		}
		// round 2
		order2 := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		s2 := []uint8{3, 5, 9, 13}
		for i, xi := range order2 {
			k := uint32(0x5A827999)
			switch i % 4 {
			case 0:
				a = md4Rol(a+md4G(b, c, d)+X[xi]+k, s2[0])
			case 1:
				d = md4Rol(d+md4G(a, b, c)+X[xi]+k, s2[1])
			case 2:
				c = md4Rol(c+md4G(d, a, b)+X[xi]+k, s2[2])
			case 3:
				b = md4Rol(b+md4G(c, d, a)+X[xi]+k, s2[3])
			}
		}
		// round 3
		order3 := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		s3 := []uint8{3, 9, 11, 15}
		for i, xi := range order3 {
			k := uint32(0x6ED9EBA1)
			switch i % 4 {
			case 0:
				a = md4Rol(a+md4H(b, c, d)+X[xi]+k, s3[0])
			case 1:
				d = md4Rol(d+md4H(a, b, c)+X[xi]+k, s3[1])
			case 2:
				c = md4Rol(c+md4H(d, a, b)+X[xi]+k, s3[2])
			case 3:
				b = md4Rol(b+md4H(c, d, a)+X[xi]+k, s3[3])
			}
		}
		a0 += a
		b0 += b
		c0 += c
		d0 += d
	}

	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], a0)
	binary.LittleEndian.PutUint32(out[4:8], b0)
	binary.LittleEndian.PutUint32(out[8:12], c0)
	binary.LittleEndian.PutUint32(out[12:16], d0)
	return out
}
