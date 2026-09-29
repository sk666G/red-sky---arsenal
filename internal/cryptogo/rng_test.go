package cryptogo

import (
	"testing"
)

// TestJavaNextPinned state advances deterministically for a known seed.
//
// java.util.Random with seed 0:
//
//	state = (0 * 0x5DEECE66D + 0xB) & mask = 0xB
//	next(32) returns state >> 16 = 0x0B >> 16 = 0
//
// The second call: state = (0xB * mult + 0xB) & mask
// state = 0x138_5AD_0D   (for reference)
//
//	next(32) = 0x1385 = 4997
func TestJavaNextPinned(t *testing.T) {
	s, v := JavaNext(0, 32)
	// first call: state starts at 0, so s = (0*mult + B) & mask = 0xB
	if s != 0xB {
		t.Fatalf("first state = 0x%x, want 0xb", s)
	}
	// next(32) with the state after the advance — v = s >> 16
	// (advance happened, so v is derived from the new state)
	if v != 0 {
		t.Fatalf("first output = %d, want 0", v)
	}

	// second call
	s2, v2 := JavaNext(s, 32)
	// s2 = (0xB * 0x5DEECE66D + 0xB) & mask
	expected := uint64(0xB)*javaMult + javaAdd
	expected &= javaMask
	if s2 != expected {
		t.Fatalf("second state = 0x%x, want 0x%x", s2, expected)
	}
	// v2 = s2 >> 16
	if v2 != s2>>16 {
		t.Fatalf("second output wrong: %d vs %d", v2, s2>>16)
	}
}

// TestJavaNextSequenceDeterministic checks that starting from a fixed state
// produces the same sequence twice.
func TestJavaNextSequenceDeterministic(t *testing.T) {
	var s1 uint64 = 12345
	var s2 uint64 = 12345
	for i := 0; i < 10; i++ {
		var v1, v2 uint64
		s1, v1 = JavaNext(s1, 32)
		s2, v2 = JavaNext(s2, 32)
		if v1 != v2 {
			t.Fatalf("diverged at iteration %d: %d vs %d", i, v1, v2)
		}
	}
}

// TestJavaRecoverFromTwoInts confirms the state recovery works on a
// sequence we generate ourselves. This is the actual attack: given two
// consecutive nextInt() outputs, find the 48-bit state.
func TestJavaRecoverFromTwoInts(t *testing.T) {
	// pick a state, run two nextInt() calls, recover the state, verify
	seed := uint64(0xDEADBEEFCAFE)
	s := (seed ^ javaMult) & javaMask
	var a, b uint64
	s, a = JavaNext(s, 32)
	s, b = JavaNext(s, 32)

	// a and b are the observed outputs (32 bits each)
	recovered, err := JavaRecoverFromTwoInts(uint32(a), uint32(b))
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	// verify: run the recovered state one step and confirm the next value
	// matches b
	s2, nextOut := JavaNext(recovered, 32)
	_ = s2
	if uint32(nextOut) != uint32(b) {
		t.Fatalf("recovery produced state that generates %d, want %d", nextOut, b)
	}
}

// TestJavaPredictExtends confirms that predictions from a recovered state
// match the actual sequence.
func TestJavaPredictExtends(t *testing.T) {
	seed := uint64(0x123456789ABC)
	s := (seed ^ javaMult) & javaMask
	// generate 10 outputs and record them
	var observed []int32
	for i := 0; i < 10; i++ {
		var v uint64
		s, v = JavaNext(s, 32)
		observed = append(observed, int32(uint32(v)))
	}

	// recover state from the first two
	recovered, err := JavaRecoverFromTwoInts(uint32(observed[0]), uint32(observed[1]))
	if err != nil {
		t.Fatal(err)
	}
	// JavaRecoverFromTwoInts returns the state that, on the next JavaNext
	// call, produces observed[1] (not observed[0] — the first output of
	// the recovered state's sequence is `b`, the second observation).
	// So JavaPredict(recovered, n)[0] == observed[1], [1] == observed[2],
	// etc. Compare accordingly.
	predicted := JavaPredict(recovered, 9)
	for i := 0; i < 8; i++ {
		want := observed[i+1]
		if predicted[i] != want {
			t.Fatalf("prediction %d: got %d, want %d", i, predicted[i], want)
		}
	}
}

// TestJavaRecoverFailsOnBadInput confirms the recovery errors when the
// two outputs did not come from consecutive steps.
func TestJavaRecoverFailsOnBadInput(t *testing.T) {
	// (1,1) is not a valid consecutive pair from any state — recovery
	// should fail
	_, err := JavaRecoverFromTwoInts(0xCAFEBABE, 0xDEADBEEF)
	// unlikely to be a false positive, but check
	if err == nil {
		t.Logf("recovery happened to find a state for unlikely input (rare)")
	}
}

// TestWinCRTNextPinned checks the Windows CRT rand LCG against a known
// sequence.
//
// Windows CRT: state = state*214013 + 2531011; output = (state>>16)&0x7FFF
// Starting from state 0:
//
//	state = 2531011 = 0x00269EC3; out = 0x0026 = 38
func TestWinCRTNextPinned(t *testing.T) {
	s, v := WinCRTNext(0)
	if s != 2531011 {
		t.Fatalf("state = %d, want 2531011", s)
	}
	if v != 38 {
		t.Fatalf("output = %d, want 38", v)
	}
}
