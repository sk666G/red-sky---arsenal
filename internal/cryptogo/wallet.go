// Package cryptogo implements crypto primitives on the agent. It is the Go
// analogue of Program/crypto/ and shares the address encoding and weak-key
// family shapes with the Python side.
//
// secp256k1 is implemented from scratch on top of math/big — the Go stdlib
// does not include this curve, and pulling btcec is a heavier dependency
// than the ~80 lines of field arithmetic this needs.
//
// Addresses:
//
//	BTC P2PKH  — base58check(0x00 || RIPEMD160(SHA256(pubkey)))
//	BTC P2WPKH — bech32("bc", 0, RIPEMD160(SHA256(pubkey)))
//	ETH        — keccak256(uncompressed pubkey[1:])[12:]  (keccak, not sha3)
package cryptogo

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// secp256k1 params
var (
	secpP, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secpN, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secpGx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secpGy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

// secpPoint is an affine point. nil x means the point at infinity.
type secpPoint struct {
	x, y *big.Int
}

func modP(x *big.Int) *big.Int {
	x = new(big.Int).Mod(x, secpP)
	if x.Sign() < 0 {
		x.Add(x, secpP)
	}
	return x
}

func secpAdd(P, Q *secpPoint) *secpPoint {
	if P == nil {
		return Q
	}
	if Q == nil {
		return P
	}
	if P.x.Cmp(Q.x) == 0 {
		sum := modP(new(big.Int).Add(P.y, Q.y))
		if sum.Sign() == 0 {
			return nil // P = -Q
		}
	}

	var lam *big.Int
	if P.x.Cmp(Q.x) == 0 && P.y.Cmp(Q.y) == 0 {
		// doubling
		num := new(big.Int).Mul(P.x, P.x)
		num.Mul(num, big.NewInt(3))
		den := new(big.Int).Mul(P.y, big.NewInt(2))
		den.ModInverse(den, secpP)
		lam = new(big.Int).Mul(num, den)
		lam = modP(lam)
	} else {
		num := new(big.Int).Sub(Q.y, P.y)
		den := new(big.Int).Sub(Q.x, P.x)
		den.ModInverse(den, secpP)
		lam = new(big.Int).Mul(num, den)
		lam = modP(lam)
	}
	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, P.x)
	x3.Sub(x3, Q.x)
	x3 = modP(x3)
	y3 := new(big.Int).Sub(P.x, x3)
	y3.Mul(y3, lam)
	y3.Sub(y3, P.y)
	y3 = modP(y3)
	return &secpPoint{x: x3, y: y3}
}

func secpMul(k *big.Int, P *secpPoint) *secpPoint {
	R := (*secpPoint)(nil)
	Q := &secpPoint{x: new(big.Int).Set(P.x), y: new(big.Int).Set(P.y)}
	k = new(big.Int).Set(k)
	for k.Sign() > 0 {
		if k.Bit(0) == 1 {
			R = secpAdd(R, Q)
		}
		Q = secpAdd(Q, Q)
		k.Rsh(k, 1)
	}
	return R
}

func secpBaseMul(k *big.Int) *secpPoint {
	return secpMul(k, &secpPoint{x: secpGx, y: secpGy})
}

// PubkeyFromPriv returns the compressed 33-byte or uncompressed 65-byte
// SEC1 encoding of the public key for the given private integer.
func PubkeyFromPriv(priv *big.Int, compressed bool) ([]byte, error) {
	if priv.Sign() <= 0 || priv.Cmp(secpN) >= 0 {
		return nil, errors.New("cryptogo: priv out of range")
	}
	P := secpBaseMul(priv)
	xb := P.x.FillBytes(make([]byte, 32))
	if !compressed {
		yb := P.y.FillBytes(make([]byte, 32))
		out := make([]byte, 65)
		out[0] = 0x04
		copy(out[1:33], xb)
		copy(out[33:], yb)
		return out, nil
	}
	out := make([]byte, 33)
	if P.y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	copy(out[1:], xb)
	return out, nil
}

// --- base58check ---

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	mod := new(big.Int)
	base := big.NewInt(58)
	var out []byte
	zero := big.NewInt(0)
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		out = append([]byte{b58Alphabet[mod.Int64()]}, out...)
	}
	// leading zeros
	for _, x := range b {
		if x == 0 {
			out = append([]byte{'1'}, out...)
		} else {
			break
		}
	}
	return string(out)
}

func hash256(b []byte) []byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

func base58Check(prefix []byte, payload []byte) string {
	buf := append(prefix, payload...)
	check := hash256(buf)[:4]
	return base58Encode(append(buf, check...))
}

// --- bech32 ---

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []byte) uint32 {
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for _, c := range hrp {
		out = append(out, byte(c)>>5)
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, byte(c)&31)
	}
	return out
}

func bech32CreateChecksum(hrp string, data []byte) []byte {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}
	return out
}

func bech32ConvertBits(data []byte, fromBits, toBits uint, pad bool) []byte {
	var acc uint32
	var bits uint
	var out []byte
	maxv := uint32(1)<<toBits - 1
	for _, v := range data {
		acc = (acc << fromBits) | uint32(v)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad && bits > 0 {
		out = append(out, byte((acc<<(toBits-bits))&maxv))
	}
	return out
}

func bech32Encode(hrp string, dataVer byte, program []byte) string {
	data := []byte{dataVer}
	data = append(data, bech32ConvertBits(program, 8, 5, true)...)
	checksum := bech32CreateChecksum(hrp, data)
	combined := append(data, checksum...)
	out := hrp + "1"
	for _, d := range combined {
		out += string(bech32Charset[d])
	}
	return out
}

// --- hashes ---

// hash160 is RIPEMD160(SHA256(b)) — the standard Bitcoin hash for address
// derivation. Both hashes are inlined (ripemd160.go, keccak.go).
func hash160(b []byte) []byte {
	s := sha256.Sum256(b)
	return RIPEMD160(s[:])
}

// --- public API ---

// BrainwalletPriv is SHA256(passphrase) mod n — the classic brainwallet.
func BrainwalletPriv(passphrase string) *big.Int {
	h := sha256.Sum256([]byte(passphrase))
	priv := new(big.Int).SetBytes(h[:])
	priv.Mod(priv, secpN)
	return priv
}

// RandomPriv returns a fresh random private key in [1, n-1].
func RandomPriv() (*big.Int, error) {
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(b)
		if k.Sign() > 0 && k.Cmp(secpN) < 0 {
			return k, nil
		}
	}
}

// Addresses derives BTC P2PKH, BTC P2WPKH, and ETH addresses for the given
// private key. NOTE: P2PKH/P2WPKH use a placeholder hash in place of
// RIPEMD160 — see the placeholder160 comment.
func Addresses(priv *big.Int) (p2pkh, p2wpkh, ethAddr string, err error) {
	pubC, err := PubkeyFromPriv(priv, true)
	if err != nil {
		return "", "", "", err
	}
	pubU, err := PubkeyFromPriv(priv, false)
	if err != nil {
		return "", "", "", err
	}
	h160 := hash160(pubC)

	p2pkh = base58Check([]byte{0x00}, h160)
	p2wpkh = bech32Encode("bc", 0, h160)

	// ETH: keccak256 of the uncompressed pubkey without the 0x04 prefix,
	// last 20 bytes as the address.
	h := Keccak256(pubU[1:])
	ethAddr = "0x" + hex.EncodeToString(h[12:])
	return p2pkh, p2wpkh, ethAddr, nil
}

// PrivHex returns the 32-byte zero-padded hex of a private key.
func PrivHex(priv *big.Int) string {
	return fmt.Sprintf("%064x", priv)
}
