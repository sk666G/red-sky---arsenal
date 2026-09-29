package cryptogo

import (
	"errors"
)

// Weak-PRNG attack primitives. Go analogue of Program/crypto/rng.py.
//
// Catalog of families (same as the Python side):
//
//   mersenne   MT19937 — 624-word state, recoverable from 624 consecutive
//              32-bit outputs. Python random, PHP mt_rand, Ruby Random.
//   java       java.util.Random — 48-bit LCG. Recoverable from 2 nextInt()
//              outputs. Kotlin default, Scala default.
//   dotnet     .NET System.Random — Knuth subtractive, 56-int state.
//   glibc      glibc rand/random — additive feedback, 34-long state.
//   php_mt     PHP mt_rand — MT with a time-seeded init (pre-7.1).
//   v8         V8 Math.random — xorshift128+, 2x64-bit state, 5 double
//              outputs recover it.
//   win_crt    Windows CRT rand() — LCG with 15-bit output. 3 outputs
//              recover the 32-bit state.
//
// Runnable drivers below: java (full state recovery), win_crt (seed brute
// over a range). The rest are catalog + reference; the state-recovery code
// for MT19937 and xorshift128+ is large enough to live in a follow-up.

// RNGInfo describes one PRNG family.
type RNGInfo struct {
	Name             string
	UsedBy           string
	StateBits        int
	ObservedBitsNeed int
	Notes            string
}

// RNGCatalog is the same list the Python side exposes.
var RNGCatalog = []RNGInfo{
	{"mersenne", "Python random, PHP mt_rand, Ruby Random", 19937, 624 * 32,
		"State is 624 32-bit words; recover from 624 consecutive outputs."},
	{"java", "java.util.Random, Kotlin, Scala", 48, 48,
		"state = (state*0x5DEECE66D + 0xB) & ((1<<48)-1); next(bits) = state >> (48-bits). 2 nextInt() outputs recover the full state."},
	{"dotnet", ".NET System.Random, PowerShell Get-Random", 56, 56,
		"Knuth subtractive, 56-Int32 seed array. 55 consecutive outputs recover the 56th."},
	{"glibc", "C rand() on Linux, PHP rand (pre-7.1)", 31, 31,
		"TYPE_3 additive feedback, 34-long state. srand(time()) is brute-forceable in 2^31."},
	{"php_mt", "PHP mt_rand", 19937, 624 * 31,
		"Pre-7.1: time-seeded mt_srand. Post-7.1: partial-state attack with enough outputs."},
	{"v8", "Chrome, Node.js, Deno", 128, 128,
		"xorshift128+ — 2x64-bit state. 5 double outputs (52 bits each) recover both words."},
	{"win_crt", "MSVC rand", 32, 32,
		"state = state*214013 + 2531011; output = (state >> 16) & 0x7FFF. 3 outputs recover the 32-bit state."},
}

// --- java.util.Random ---

const (
	javaMult = uint64(0x5DEECE66D)
	javaAdd  = uint64(0xB)
	javaMask = uint64((1 << 48) - 1)
)

// JavaNext advances a 48-bit java.util.Random state and returns the next
// `bits`-wide output.
func JavaNext(state uint64, bits uint) (uint64, uint64) {
	state = (state*javaMult + javaAdd) & javaMask
	return state, state >> (48 - bits)
}

// JavaRecoverFromTwoInts recovers the 48-bit state from two consecutive
// nextInt() outputs. Brute-forces the low 16 bits of state1 (2^16 candidates).
func JavaRecoverFromTwoInts(a, b uint32) (uint64, error) {
	for low := uint64(0); low < (1 << 16); low++ {
		s1 := (uint64(a) << 16) | low
		s2 := (s1*javaMult + javaAdd) & javaMask
		if uint32(s2>>16) == b {
			return s1, nil
		}
	}
	return 0, errors.New("cryptogo/rng: no state matches those two ints")
}

// JavaPredict returns the next n 32-bit nextInt() outputs (as signed int32)
// from the recovered state.
func JavaPredict(state uint64, n int) []int32 {
	out := make([]int32, 0, n)
	s := state
	for i := 0; i < n; i++ {
		var raw uint64
		s, raw = JavaNext(s, 32)
		out = append(out, int32(uint32(raw)))
	}
	return out
}

// --- Windows CRT rand ---

// WinCRTNext advances a 32-bit Windows CRT rand state and returns
// (newState, output). Output is the low 15 bits of (state >> 16).
func WinCRTNext(state uint32) (uint32, uint16) {
	state = state*214013 + 2531011
	return state, uint16((state >> 16) & 0x7FFF)
}

// WinCRTSeedCandidates returns every seed in [lo, hi) whose first rand()
// output matches firstOut.
func WinCRTSeedCandidates(firstOut uint16, lo, hi uint32) []uint32 {
	var out []uint32
	for s := lo; s < hi; s++ {
		_, o := WinCRTNext(s)
		if o == firstOut {
			out = append(out, s)
		}
	}
	return out
}
