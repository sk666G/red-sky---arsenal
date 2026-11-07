//go:build windows

package evasion

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SpoofedSleep sleeps for d with the current thread's stack shaped to
// look like a normal Windows sleep — kernel32!SleepEx called from the
// thread's entry point — instead of the Go runtime netpoller frames a
// stack walker would otherwise see.
//
// Approach A from docs/105c-rop-spoof-plan.md:
//  1. LockOSThread — pin the goroutine to one thread.
//  2. Resolve kernel32!SleepEx + ntdll!NtWaitForSingleObject via
//     LazyProc (cached on first call).
//  3. Build a signalled-on-timeout event object.
//  4. Wait via NtWaitForSingleObject for d.
//  5. Close the event, unlock.
//
// Layer 1 ships the kernel32/ntdll wait without the fake frame push.
// Layer 2 (105c-3) adds the frame push + entersyscall/exitsyscall.
func SpoofedSleep(d time.Duration) error {
	// Fast path: caller asked for a normal sleep, let the runtime handle it.
	if d <= 0 {
		time.Sleep(d)
		return nil
	}

	procs, perr := loadSpoofProcs()
	if perr != nil {
		// Fallback to plain sleep if the proc resolution failed. The
		// sleepmask + crypto layers are still in place — the spoof is
		// defense-in-depth, not a hard requirement.
		time.Sleep(d)
		return perr
	}

	// Create a manual-reset event that starts unsignalled.
	ev, _, _ := procs.createEventW.Call(0, 0, 0, 0)
	if ev == 0 {
		time.Sleep(d)
		return fmt.Errorf("evasion: CreateEventW failed")
	}
	defer procs.closeHandle.Call(ev)

	// Wait — 100-nanosecond units, negative for relative.
	wait100ns := int64(-d.Nanoseconds() / 100)
	// NtWaitForSingleObject(handle, alertable, *timeout)
	procs.ntWait.Call(ev, 0, uintptr(unsafe.Pointer(&wait100ns)))
	return nil
}

type spoofProcs struct {
	kernel32     *windows.LazyDLL
	ntdll        *windows.LazyDLL
	createEventW *windows.LazyProc
	closeHandle  *windows.LazyProc
	ntWait       *windows.LazyProc
	sleepEx      *windows.LazyProc
}

var (
	procsOnce sync.Once
	procsVal  *spoofProcs
	procsErr  error
)

func loadSpoofProcs() (*spoofProcs, error) {
	procsOnce.Do(func() {
		p := &spoofProcs{
			kernel32:     windows.NewLazySystemDLL("kernel32.dll"),
			ntdll:        windows.NewLazySystemDLL("ntdll.dll"),
			createEventW: windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateEventW"),
			closeHandle:  windows.NewLazySystemDLL("kernel32.dll").NewProc("CloseHandle"),
			ntWait:       windows.NewLazySystemDLL("ntdll.dll").NewProc("NtWaitForSingleObject"),
			sleepEx:      windows.NewLazySystemDLL("kernel32.dll").NewProc("SleepEx"),
		}
		procsVal = p
	})
	return procsVal, procsErr
}
