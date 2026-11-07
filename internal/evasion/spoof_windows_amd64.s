//go:build windows && amd64

#include "textflag.h"

// func getSP() uintptr
// Returns the current stack pointer.
TEXT ·getSP(SB),NOSPLIT,$0-8
	MOVQ SP, AX
	MOVQ AX, ret+0(FP)
	RET

// func setSP(sp uintptr)
// Sets the current stack pointer to the given value. Caller must restore
// any change with the same primitive.
TEXT ·setSP(SB),NOSPLIT,$0-8
	MOVQ sp+0(FP), AX
	MOVQ AX, SP
	RET
